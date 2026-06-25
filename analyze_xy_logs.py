#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分析 xy.bioon.com.log，识别 WAF 未覆盖的恶意访问模式。
"""

import re
import os
import sys
from collections import Counter
from urllib.parse import unquote

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

LOG_FILE = "D:\\lumin\\desktop\\xy.bioon.com.log"
WAFCF_DIR = "wafconf"

WAF_BLOCK_STATUSES = {400, 403, 404, 444, 503}


def parse_log_line(line):
    """解析 xy.bioon.com.log 格式：
    client_ip upstream_ip - - [time] "request" status size "referer" "UA" upstream_addr ...
    """
    pattern = r'^(\S+)\s+(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]*?)"\s+(\d{3})\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"'
    m = re.match(pattern, line)
    if not m:
        return None
    client_ip, upstream_ip, time, request, status, size, referer, ua = m.groups()
    req_parts = request.split(' ', 2)
    if len(req_parts) < 2:
        return None
    method = req_parts[0]
    uri = req_parts[1]
    protocol = req_parts[2] if len(req_parts) >= 3 else ''
    return {
        'client_ip': client_ip,
        'upstream_ip': upstream_ip,
        'time': time,
        'method': method,
        'uri': uri,
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


def check_traversal(uri):
    pattern = r'(\.\./|\.(%2e)|(%2e)\.|%2e%2e|%252e|\%00)'
    if re.search(pattern, uri, re.IGNORECASE):
        return ('TRAVERSAL', pattern)
    return None


def check_args(uri, rules):
    """检查 URL 查询参数"""
    if '?' not in uri:
        return None
    query = uri.split('?', 1)[1]
    decoded = unquote(query)
    for rule in rules:
        if lua_re_match(decoded, rule):
            return ('ARGS', rule)
    return None


def is_suspicious_path(uri):
    """识别常见扫描路径（即使不在当前规则中）"""
    suspicious_patterns = [
        r'\.env',
        r'\.git',
        r'\.svn',
        r'\.htaccess',
        r'\.well-known.*backup',
        r'phpmyadmin',
        r'admin\.php',
        r'wp-login',
        r'wp-config',
        r'/admin/',
        r'/manager/',
        r'/console',
        r'/actuator',
        r'/api-docs',
        r'/swagger',
        r'/solr',
        r'/jmx-console',
        r'/invoker',
        r'/setup\.php',
        r'/install\.php',
        r'/config\.xml',
        r'/server-status',
        r'/phpinfo',
        r'/info\.php',
        r'\.sql',
        r'\.bak',
        r'\.zip',
        r'\.tar\.gz',
        r'\.rar',
        r'/backup/',
        r'/test/',
        r'/debug/',
        r'/tmp/',
        r'/uploads?/.*\.php',
        r'eval\(',
        r'system\(',
        r'shell_exec',
        r'<script',
        r'javascript:',
        r'union\s+select',
        r'sleep\(',
        r'benchmark\(',
        r'%3Cscript',
        r'%3C%73%63%72%69%70%74',
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

    # 统计
    status_counter = Counter(e['status'] for e in entries)
    print("状态码分布:")
    for status, count in sorted(status_counter.items()):
        print(f"  {status}: {count}")
    print()

    # 1. 命中 WAF 规则但未拦截的请求
    not_blocked = []
    blocked = []
    not_covered_suspicious = []
    not_covered_404 = []
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
        h = check_traversal(uri)
        if h:
            hits.append(h)
        h = check_args(uri, args_rules)
        if h:
            hits.append(h)

        if hits:
            if status in WAF_BLOCK_STATUSES:
                blocked.append((req, hits))
            else:
                not_blocked.append((req, hits))
        else:
            # 未命中任何 WAF 规则
            suspicious = is_suspicious_path(uri)
            if suspicious:
                not_covered_suspicious.append((req, suspicious))
            elif status == 404:
                path_404_counter[uri.split('?')[0]] += 1
                ip_404_counter[req['client_ip']] += 1

        ip_counter[req['client_ip']] += 1

    print("=" * 80)
    print(f"一、命中 WAF 规则且被拦截的请求: {len(blocked)} 条")
    print("=" * 80)
    # 只展示前 20 条
    for req, hits in blocked[:20]:
        hit_desc = ' | '.join([f"{h[0]}" for h in hits])
        print(f"  [{req['status']}] {req['client_ip']} {req['method']} {req['uri'][:100]}")
        print(f"       UA: {req['ua'][:60]} 命中: {hit_desc}")
    print()

    print("=" * 80)
    print(f"二、命中 WAF 规则但未被拦截的请求（漏过）: {len(not_blocked)} 条")
    print("=" * 80)
    for req, hits in not_blocked[:30]:
        hit_desc = ' | '.join([f"{h[0]}: {h[1][:50]}" for h in hits])
        print(f"  [{req['status']}] {req['client_ip']} {req['method']} {req['uri'][:100]}")
        print(f"       UA: {req['ua'][:60]} 应命中: {hit_desc}")
    print()

    print("=" * 80)
    print(f"三、未命中 WAF 规则的可疑请求: {len(not_covered_suspicious)} 条")
    print("=" * 80)
    for req, pat in not_covered_suspicious[:50]:
        print(f"  [{req['status']}] {req['client_ip']} {req['method']} {req['uri'][:120]}")
        print(f"       UA: {req['ua'][:60]} 可疑特征: {pat}")
    print()

    print("=" * 80)
    print("四、404 路径 TOP 30（非 WAF 规则覆盖）")
    print("=" * 80)
    for path, count in path_404_counter.most_common(30):
        print(f"  {count:5d}  {path[:120]}")
    print()

    print("=" * 80)
    print("五、请求量 TOP 20 的 IP")
    print("=" * 80)
    for ip, count in ip_counter.most_common(20):
        print(f"  {count:6d}  {ip}")
    print()

    print("=" * 80)
    print("六、404 请求量 TOP 20 的 IP")
    print("=" * 80)
    for ip, count in ip_404_counter.most_common(20):
        print(f"  {count:6d}  {ip}")
    print()


if __name__ == '__main__':
    main()
