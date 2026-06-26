#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分析 ir.medsci.cn.log，根据当前 WAF 规则判断攻击与未覆盖行为。
日志格式有两种：
  - <upstream> <client_ip> - - [time] "..." ...（第一字段可能是 -）
  - <client_ip> <upstream_ip> - - [time] "..." ...
UA 后面还有 upstream_addr、响应时间等字段，需要忽略。
"""

import re
import os
import sys
from collections import Counter
from urllib.parse import unquote

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

LOG_FILE = r"D:\lumin\desktop\ir.medsci.cn.log"
WAFCF_DIR = "wafconf"

WAF_BLOCK_STATUSES = {400, 403, 404, 444, 503}


def parse_log_line(line):
    """解析单条日志，返回 client_ip 等字段"""
    # 先取前 4 个字段判断格式
    fields = line.split(None, 3)
    if len(fields) < 4:
        return None
    # 如果第一个字段是 '-'，则真实客户端 IP 是第二个
    if fields[0] == '-':
        client_ip = fields[1]
    else:
        client_ip = fields[0]

    # 用正则提取主要字段，忽略 UA 后面的 upstream/time 等
    pattern = (
        r'^(?:\S+\s+)?(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]*?)"\s+'
        r'(\d{3})\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"'
    )
    m = re.match(pattern, line)
    if not m:
        return None
    _, time, request, status, size, referer, ua = m.groups()
    req_parts = request.split(' ', 2)
    if len(req_parts) < 2:
        method = req_parts[0]
        uri_with_query = '/'
        protocol = ''
    else:
        method = req_parts[0]
        uri_with_query = req_parts[1]
        protocol = req_parts[2] if len(req_parts) >= 3 else ''
    return {
        'ip': client_ip,
        'time': time,
        'method': method,
        'uri': uri_with_query,
        'protocol': protocol,
        'request': request,
        'status': int(status),
        'size': int(size),
        'referer': referer,
        'ua': ua,
        'raw': line.strip(),
    }


def read_rules(filename):
    path = os.path.join(WAFCF_DIR, filename)
    rules = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            rules.append(line)
    return rules


def read_tagged_rules(filename):
    path = os.path.join(WAFCF_DIR, filename)
    rules = []
    current_tag = 'core'
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith('#'):
                tag_match = re.match(r'^#\s*\[([^\]]+)\]', line)
                if tag_match:
                    current_tag = tag_match.group(1)
                continue
            rules.append((line, current_tag))
    return rules


def lua_re_match(text, pattern):
    if text is None:
        return False
    text = str(text)
    pat = pattern.replace('%.', r'\.').replace('%2e', r'%2e').replace('%2E', r'%2E')
    try:
        return re.search(pat, text, re.IGNORECASE) is not None
    except re.error:
        try:
            pat2 = pat.replace(r'(?<!', r'(').replace(r'(?!)', r'()')
            return re.search(pat2, text, re.IGNORECASE) is not None
        except Exception:
            return False


def check_ua(ua, rules):
    if not ua or ua == '-':
        return None
    for rule in rules:
        if lua_re_match(ua, rule):
            return ('UA', rule)
    return None


def check_method(method, rules):
    for rule in rules:
        if lua_re_match(method, rule):
            return ('METHOD', rule)
    return None


def check_dangerous(uri, rules):
    for rule, tag in rules:
        if lua_re_match(uri, rule):
            return ('DANGEROUS', rule, tag)
    return None


def check_url(uri, rules):
    for rule in rules:
        if lua_re_match(uri, rule):
            return ('URL', rule)
    return None


def check_args(uri, rules):
    if '?' not in uri:
        return None
    query = uri.split('?', 1)[1]
    decoded = unquote(query)
    for rule in rules:
        if lua_re_match(decoded, rule):
            return ('ARGS', rule)
    return None


def check_referer(ref, rules):
    if not ref or ref == '-':
        return None
    for rule in rules:
        if lua_re_match(ref, rule):
            return ('REFERER', rule)
    return None


def check_traversal(uri):
    pattern = r'(\.\./|\.(%2e)|(%2e)\.|%2e%2e|%252e|\%00)'
    if re.search(pattern, uri, re.IGNORECASE):
        return ('TRAVERSAL', pattern)
    return None


def is_scanner_or_probe(req):
    ua = req['ua'].lower()
    uri = req['uri'].lower()
    method = req['method']

    scanner_uas = [
        'curl', 'wget', 'python-requests', 'python-urllib', 'http banner detection',
        'palo alto', 'cortex', 'xpanse', 'l9explore', 'l9tcpid', 'zgrab', 'nmap',
        'nikto', 'acunetix', 'masscan', 'wpscan', 'sqlmap', 'gobuster', 'ffuf',
        'censys', 'shodan', 'zoomeye', 'nuclei'
    ]
    if any(s in ua for s in scanner_uas):
        return True

    probe_uris = [
        '/version', '/v1', '/next.config.js', '/geoserver/web/', '/owa/auth/logon.aspx',
        '/developmentserver/metadatauploader', '/.git/config', '/.gitconfig',
        '/.env', '/server/.env', '/.git-credentials', '/api/auth/validate-sso'
    ]
    if any(uri.startswith(p) for p in probe_uris):
        return True

    if method == 'POST' and uri == '/':
        return True

    if method not in ('GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'PATCH', 'DELETE'):
        return True

    if req['ua'] == '-' or req['ua'] == 'Mozilla/5.0':
        if uri in ('/', '/version', '/v1', '/api/auth/validate-sso'):
            return True

    if '%' in req['uri'] and uri != '/':
        decoded = unquote(req['uri'])
        if any(ord(c) > 127 for c in decoded):
            return True

    return False


def is_suspicious_path(uri):
    suspicious_patterns = [
        r'\.env', r'\.git', r'\.svn', r'\.htaccess', r'\.well-known.*backup',
        r'phpmyadmin', r'admin\.php', r'wp-login', r'wp-config', r'/admin/',
        r'/manager/', r'/console', r'/actuator', r'/api-docs', r'/swagger',
        r'/solr', r'/jmx-console', r'/invoker', r'/setup\.php', r'/install\.php',
        r'/config\.xml', r'/server-status', r'/phpinfo', r'/info\.php',
        r'\.sql', r'\.bak', r'\.zip', r'\.tar\.gz', r'\.rar', r'/backup/',
        r'/test/', r'/debug/', r'/tmp/', r'/uploads?/.*\.php', r'eval\(',
        r'system\(', r'shell_exec', r'<script', r'javascript:', r'union\s+select',
        r'sleep\(', r'benchmark\(', r'%3Cscript', r'%3C%73%63%72%69%70%74',
        r'wp-content/.*\.php\?', r'wp-admin', r'xmlrpc\.php', r'wp-login\.php',
        r'wp-json', r'wlwmanifest\.xml', r'/wp-config'
    ]
    decoded = unquote(uri)
    for pat in suspicious_patterns:
        if re.search(pat, decoded, re.IGNORECASE):
            return pat
    return None


def main():
    ua_rules = read_rules('user-agent')
    method_rules = read_rules('method')
    dangerous_rules = read_tagged_rules('dangerous')
    url_rules = read_rules('url')
    args_rules = read_rules('args')
    referer_rules = read_rules('referer')

    entries = []
    parse_errors = 0
    with open(LOG_FILE, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            if not line.strip():
                continue
            parsed = parse_log_line(line)
            if parsed:
                entries.append(parsed)
            else:
                parse_errors += 1

    print(f"共解析 {len(entries)} 条日志，解析失败 {parse_errors} 条\n")

    status_counter = Counter(e['status'] for e in entries)
    print("状态码分布:")
    for status, count in sorted(status_counter.items()):
        print(f"  {status}: {count}")
    print()

    blocked = []
    not_blocked = []
    unknown_400 = []
    not_covered_suspicious = []
    path_404_counter = Counter()
    ip_counter = Counter()
    ip_404_counter = Counter()

    for req in entries:
        status = req['status']
        uri = req['uri']
        hits = []

        h = check_ua(req['ua'], ua_rules)
        if h:
            hits.append(h)
        h = check_method(req['method'], method_rules)
        if h:
            hits.append(h)
        h = check_dangerous(uri, dangerous_rules)
        if h:
            hits.append(h)
        h = check_url(uri, url_rules)
        if h:
            hits.append(h)
        h = check_args(uri, args_rules)
        if h:
            hits.append(h)
        h = check_referer(req['referer'], referer_rules)
        if h:
            hits.append(h)
        h = check_traversal(uri)
        if h:
            hits.append(h)

        if hits:
            if status in WAF_BLOCK_STATUSES:
                blocked.append((req, hits))
            else:
                not_blocked.append((req, hits))
        else:
            if status == 400 and is_scanner_or_probe(req):
                unknown_400.append(req)
            suspicious = is_suspicious_path(uri)
            if suspicious:
                not_covered_suspicious.append((req, suspicious))
            if status == 404:
                path_404_counter[uri.split('?')[0]] += 1
                ip_404_counter[req['ip']] += 1

        ip_counter[req['ip']] += 1

    print("=" * 80)
    print(f"一、命中 WAF 规则且被拦截的请求: {len(blocked)} 条")
    print("=" * 80)
    for req, hits in blocked[:30]:
        hit_desc = ' | '.join([f"{h[0]}" for h in hits])
        print(f"  [{req['status']}] {req['ip']} {req['method']} {req['uri'][:100]}")
        print(f"       UA: {req['ua'][:80]}  命中: {hit_desc}")
    print()

    print("=" * 80)
    print(f"二、命中 WAF 规则但未被拦截的请求（漏过）: {len(not_blocked)} 条")
    print("=" * 80)
    for req, hits in not_blocked[:50]:
        hit_desc = ' | '.join([f"{h[0]}: {str(h[1])[:60]}" for h in hits])
        print(f"  [{req['status']}] {req['ip']} {req['method']} {req['uri'][:100]}")
        print(f"       UA: {req['ua'][:80]}  应命中: {hit_desc}")
    print()

    print("=" * 80)
    print(f"三、状态码 400 但未命中 WAF 规则的扫描/探测请求: {len(unknown_400)} 条")
    print("=" * 80)
    for req in unknown_400[:30]:
        print(f"  [{req['status']}] {req['ip']} {req['method']} {req['uri'][:100]}")
        print(f"       UA: {req['ua'][:80]}")
    print()

    print("=" * 80)
    print(f"四、未命中 WAF 规则的可疑请求（可能未覆盖）: {len(not_covered_suspicious)} 条")
    print("=" * 80)
    for req, pat in not_covered_suspicious[:100]:
        print(f"  [{req['status']}] {req['ip']} {req['method']} {req['uri'][:120]}")
        print(f"       UA: {req['ua'][:80]}  可疑特征: {pat}")
    print()

    print("=" * 80)
    print("五、状态码 200/301/308 的扫描/探测行为（未被拦截）")
    print("=" * 80)
    scan_success = []
    for req in entries:
        if req['status'] in WAF_BLOCK_STATUSES:
            continue
        if is_scanner_or_probe(req) and req not in [x[0] for x in not_blocked]:
            scan_success.append(req)
    for req in scan_success[:100]:
        print(f"  [{req['status']}] {req['ip']} {req['method']} {req['uri'][:100]}")
        print(f"       UA: {req['ua'][:80]}")
    print(f"   合计 {len(scan_success)} 条\n")

    print("=" * 80)
    print("六、404 路径 TOP 30（未命中 WAF 规则）")
    print("=" * 80)
    for path, count in path_404_counter.most_common(30):
        print(f"  {count:5d}  {path[:120]}")
    print()

    print("=" * 80)
    print("七、请求量 TOP 30 的 IP")
    print("=" * 80)
    for ip, count in ip_counter.most_common(30):
        print(f"  {count:6d}  {ip}")
    print()

    print("=" * 80)
    print("八、404 请求量 TOP 30 的 IP")
    print("=" * 80)
    for ip, count in ip_404_counter.most_common(30):
        print(f"  {count:6d}  {ip}")
    print()


if __name__ == '__main__':
    main()
