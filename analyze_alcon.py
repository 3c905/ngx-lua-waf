#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分析 Nginx 访问日志，输出 WAF 规则缺口、需补充规则建议及可疑 IP。

只输出统计和需要关注的攻击面，不逐条打印正常访问。

默认用法（Linux 生产环境）：
    ./analyze_alcon.py

自定义路径：
    ./analyze_alcon.py --log /var/log/nginx/access.log --wafconf /etc/waf/wafconf

需要看完整明细时加 --detail：
    ./analyze_alcon.py --detail
"""

import re
import os
import sys
import argparse
from collections import Counter, defaultdict
from urllib.parse import unquote, urlparse

# 兼容不同运行环境：Windows 本地调试 / Linux 服务器
try:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8')
except Exception:
    pass

DEFAULT_LOG_FILE = "/u/medsci/logs/nginx/www.alcon.cn.log"
DEFAULT_WAFCF_DIR = "/u/nginx/ngx_lua_waf/wafconf"
WAF_BLOCK_STATUSES = {400, 403, 404, 444, 503}

# 预编译的启发式正则
_SCANNER_UA_SET = {
    'curl', 'wget', 'python-requests', 'python-urllib', 'http banner detection',
    'palo alto', 'cortex', 'xpanse', 'l9explore', 'l9tcpid', 'zgrab', 'nmap',
    'nikto', 'acunetix', 'masscan', 'wpscan', 'sqlmap', 'gobuster', 'ffuf',
    'censys', 'shodan', 'zoomeye', 'nuclei'
}

_PROBE_URI_STARTS = (
    '/version', '/v1', '/next.config.js', '/geoserver/web/', '/owa/auth/logon.aspx',
    '/developmentserver/metadatauploader', '/.git/config', '/.gitconfig',
    '/.env', '/server/.env', '/.git-credentials', '/api/auth/validate-sso'
)

_SUSPICIOUS_PATH_RE = re.compile(
    r'\.env\b|\.git\b|\.svn\b|\.htaccess\b|\.well-known.*backup|phpmyadmin|admin\.php|'
    r'wp-login|wp-config|/admin/|/manager/|/console|/actuator|/api-docs|/swagger|'
    r'/solr|/jmx-console|/invoker|/setup\.php|/install\.php|/config\.xml|'
    r'/server-status|/phpinfo|/info\.php|\.sql\b|\.bak\b|\.zip\b|\.tar\.gz\b|\.rar\b|'
    r'/backup/|/test/|/debug/|/tmp/|/uploads?/.*\.php|eval\(|system\(|shell_exec|'
    r'<script|javascript:|union\s+select|sleep\(|benchmark\(|%3Cscript|'
    r'%3C%73%63%72%69%70%74|wp-json|xmlrpc\.php|webuploader|/Admin/|fckeditor|'
    r'kindeditor|ueditor|/console/|/manager/|/setup|/install',
    re.IGNORECASE
)

# 观察到的可疑关键字 -> 建议补充的规则（供参考）
_RULE_ADVICE_MAP = [
    (re.compile(r'phpinfo', re.I), 'wafconf/dangerous 或 wafconf/url', 'phpinfo 探测路径'),
    (re.compile(r'/admin/|admin\.php|/manager/|/console/', re.I), 'wafconf/dangerous', '后台/管理入口探测'),
    (re.compile(r'webuploader|fckeditor|kindeditor|ueditor', re.I), 'wafconf/dangerous', '编辑器上传接口探测'),
    (re.compile(r'wp-json|xmlrpc\.php|wp-login|wp-config', re.I), 'wafconf/dangerous', 'WordPress 敏感接口探测'),
    (re.compile(r'\.env|\.git|\.svn|\.htaccess|\.bak|\.sql|\.tar\.gz|\.rar|\.zip', re.I),
     'wafconf/url / wafconf/dangerous', '敏感文件/备份泄露探测'),
    (re.compile(r'EXTRACTVALUE|UPDATEXML|UNION\s+SELECT|SLEEP\s*\(|BENCHMARK\s*\(|/\*!50000|INTO\s+(OUT|DUMP)FILE|information_schema', re.I),
     'wafconf/dangerous', 'URI 路径 SQL 注入'),
    (re.compile(r'AvaliablePing', re.I), 'wafconf/user-agent', 'CC/压力测试工具 UA'),
]


def parse_args():
    parser = argparse.ArgumentParser(
        description="分析 Nginx 访问日志，输出 WAF 规则缺口、需补充规则建议及可疑 IP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例：
  ./analyze_alcon.py
  ./analyze_alcon.py --log /u/medsci/logs/nginx/www.alcon.cn.log --wafconf /u/nginx/ngx_lua_waf/wafconf
  ./analyze_alcon.py --detail
        """
    )
    parser.add_argument('--log', default=DEFAULT_LOG_FILE,
                        help=f'Nginx 访问日志路径（默认：{DEFAULT_LOG_FILE}）')
    parser.add_argument('--wafconf', default=DEFAULT_WAFCF_DIR,
                        help=f'WAF 规则目录（默认：{DEFAULT_WAFCF_DIR}）')
    parser.add_argument('--detail', action='store_true',
                        help='输出完整命中/未命中明细（默认只输出统计和建议）')
    parser.add_argument('--top', type=int, default=30,
                        help='聚合后最多展示多少条（默认：30）')
    return parser.parse_args()


def parse_log_line(line):
    """解析单条 Nginx 访问日志，支持变长 XFF 头部"""
    pattern = (
        r'^(.*?)\s+-\s+-\s+\[([^\]]+)\]\s+"([^"]*?)"\s+'
        r'(\d{3})\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"'
    )
    m = re.match(pattern, line)
    if not m:
        return None
    leading, time, request, status, size, referer, ua = m.groups()

    leading_parts = leading.split()
    if not leading_parts:
        return None
    client_ip = leading_parts[-1]

    req_parts = request.split(' ', 2)
    if len(req_parts) < 2:
        method, uri_with_query, protocol = req_parts[0], '/', ''
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


def read_rules(wafconf_dir, filename):
    path = os.path.join(wafconf_dir, filename)
    rules = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            rules.append(line)
    return rules


def read_tagged_rules(wafconf_dir, filename):
    path = os.path.join(wafconf_dir, filename)
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


def classify_request(req, ua_rules, method_rules, dangerous_rules, url_rules,
                     args_rules, referer_rules):
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
    return hits


def is_scanner_or_probe(req):
    ua = req['ua'].lower()
    uri = req['uri'].lower()
    method = req['method']

    if any(s in ua for s in _SCANNER_UA_SET):
        return True
    if uri.startswith(_PROBE_URI_STARTS):
        return True
    if method == 'POST' and uri == '/':
        return True
    if method not in ('GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'PATCH', 'DELETE'):
        return True
    if req['ua'] in ('-', 'Mozilla/5.0') and uri in ('/', '/version', '/v1', '/api/auth/validate-sso'):
        return True
    return False


def is_suspicious_path(uri):
    m = _SUSPICIOUS_PATH_RE.search(unquote(uri))
    return m.group(0) if m else None


def normalize_path(uri):
    """用于聚合展示：保留 path，截断过长的 query"""
    path = urlparse(uri).path
    decoded = unquote(path)
    return decoded[:120]


def gen_rule_advice(sample_urls):
    """根据观察到的未覆盖 URL 给出规则补充建议"""
    advice = []
    matched_keywords = set()
    for url in sample_urls:
        decoded = unquote(url)
        for pattern, target, desc in _RULE_ADVICE_MAP:
            if pattern.search(decoded):
                key = (target, desc)
                if key not in matched_keywords:
                    matched_keywords.add(key)
                    advice.append((target, desc, url))
    return advice


def main():
    args = parse_args()
    log_file = args.log
    wafconf_dir = args.wafconf
    top_n = args.top
    detail = args.detail

    if not os.path.isdir(wafconf_dir):
        print(f"[ERROR] WAF 规则目录不存在: {wafconf_dir}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(log_file):
        print(f"[ERROR] 日志文件不存在: {log_file}", file=sys.stderr)
        sys.exit(1)

    ua_rules = read_rules(wafconf_dir, 'user-agent')
    method_rules = read_rules(wafconf_dir, 'method')
    dangerous_rules = read_tagged_rules(wafconf_dir, 'dangerous')
    url_rules = read_rules(wafconf_dir, 'url')
    args_rules = read_rules(wafconf_dir, 'args')
    referer_rules = read_rules(wafconf_dir, 'referer')

    entries = []
    parse_errors = 0
    with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            if not line.strip():
                continue
            parsed = parse_log_line(line)
            if parsed:
                entries.append(parsed)
            else:
                parse_errors += 1

    total = len(entries)
    print("=" * 80)
    print("WAF 规则缺口分析摘要")
    print("=" * 80)
    print(f"日志文件      : {log_file}")
    print(f"WAF 规则目录  : {wafconf_dir}")
    print(f"总请求数      : {total}")
    print(f"解析失败      : {parse_errors}")

    blocked = []
    not_blocked = []
    unknown_400 = []
    not_covered_suspicious = []

    # 聚合统计
    rule_hit_counter = Counter()
    rule_notblocked_counter = Counter()
    ip_info = defaultdict(lambda: {
        'count': 0, 'blocked': 0, 'not_blocked': 0,
        'suspicious': 0, 'rules': set(), 'suspicious_urls': set()
    })

    for req in entries:
        status = req['status']
        ip = req['ip']
        hits = classify_request(
            req, ua_rules, method_rules, dangerous_rules,
            url_rules, args_rules, referer_rules
        )

        ip_info[ip]['count'] += 1

        if hits:
            for h in hits:
                rule_hit_counter[h[0]] += 1
            if status in WAF_BLOCK_STATUSES:
                blocked.append((req, hits))
                ip_info[ip]['blocked'] += 1
            else:
                not_blocked.append((req, hits))
                ip_info[ip]['not_blocked'] += 1
                for h in hits:
                    rule_notblocked_counter[h[0]] += 1
            for h in hits:
                ip_info[ip]['rules'].add(h[0])
        else:
            if status == 400 and is_scanner_or_probe(req):
                unknown_400.append(req)
            suspicious = is_suspicious_path(req['uri'])
            if suspicious:
                not_covered_suspicious.append(req)
                ip_info[ip]['suspicious'] += 1
                ip_info[ip]['suspicious_urls'].add(normalize_path(req['uri']))

    print(f"已拦截        : {len(blocked)}")
    print(f"命中但未拦截  : {len(not_blocked)}")
    print(f"400 异常未命中: {len(unknown_400)}")
    print(f"未命中可疑请求: {len(not_covered_suspicious)}")
    print()

    # 规则命中分布
    print("=" * 80)
    print("一、WAF 各模块命中分布")
    print("=" * 80)
    print(f"{'模块':<12} {'命中总数':>10} {'其中未拦截':>12}")
    for module in sorted(set(rule_hit_counter) | set(rule_notblocked_counter)):
        print(f"{module:<12} {rule_hit_counter.get(module, 0):>10} {rule_notblocked_counter.get(module, 0):>12}")
    print()

    # 命中但未拦截的聚合（按规则）
    if not_blocked:
        print("=" * 80)
        print("二、命中规则但未拦截的请求聚合（说明规则已存在但 WAF 未实际 block）")
        print("=" * 80)
        nb_by_rule = defaultdict(list)
        for req, hits in not_blocked:
            for h in hits:
                nb_by_rule[str(h[1])[:80]].append(req)
        for rule, reqs in sorted(nb_by_rule.items(), key=lambda x: -len(x[1]))[:top_n]:
            ips = Counter(r['ip'] for r in reqs)
            statuses = Counter(r['status'] for r in reqs)
            print(f"  规则: {rule}")
            print(f"       数量: {len(reqs)}  状态码: {dict(statuses)}  来源IP数: {len(ips)}")
            print(f"       TOP3 IP: {', '.join(f'{ip}({c})' for ip, c in ips.most_common(3))}")
        print()

    # 未命中规则的可疑 URL 聚合
    if not_covered_suspicious:
        print("=" * 80)
        print("三、未命中 WAF 规则的可疑 URL（需要重点补充规则）")
        print("=" * 80)
        grouped = defaultdict(lambda: {'count': 0, 'ips': Counter(), 'statuses': Counter(), 'samples': []})
        for req in not_covered_suspicious:
            path = normalize_path(req['uri'])
            g = grouped[path]
            g['count'] += 1
            g['ips'][req['ip']] += 1
            g['statuses'][req['status']] += 1
            if len(g['samples']) < 3:
                g['samples'].append(req['uri'][:120])

        for path, info in sorted(grouped.items(), key=lambda x: -x[1]['count'])[:top_n]:
            print(f"  数量: {info['count']:<5} 状态码: {dict(info['statuses'])}")
            print(f"       URL路径: {path}")
            print(f"       TOP3 IP: {', '.join(f'{ip}({c})' for ip, c in info['ips'].most_common(3))}")
            if detail:
                for s in info['samples']:
                    print(f"       示例: {s}")
        print()

        # 规则建议
        print("=" * 80)
        print("四、规则补充建议")
        print("=" * 80)
        # 用原始 URL（含 query）生成规则建议，避免 /index.php?s=/admin/... 被归到 /index.php
        all_samples = []
        for info in grouped.values():
            all_samples.extend(info['samples'])
        advice = gen_rule_advice(all_samples)
        if advice:
            seen = set()
            for target, desc, example in advice:
                key = (target, desc)
                if key in seen:
                    continue
                seen.add(key)
                print(f"  [{target}] {desc}")
                print(f"       参考示例: {example}")
        else:
            print("  根据现有可疑路径，暂无通用规则建议，请结合业务判断上述路径是否需要防护。")
        print()

        # 兜底：把未命中的可疑路径本身也列出来，方便人工判断
        if detail:
            print("  未覆盖可疑路径完整列表（去重）:")
            for path in sorted(grouped.keys())[:top_n]:
                print(f"    {path}")

    # 可疑 IP 聚合
    print("=" * 80)
    print("五、可疑 / 攻击 IP TOP")
    print("=" * 80)
    # 排序：优先看命中规则但未拦截、可疑 URL 多的 IP
    ip_list = []
    for ip, info in ip_info.items():
        score = info['not_blocked'] * 2 + info['suspicious'] + info['blocked']
        if score > 0 or info['count'] > 100:
            ip_list.append((ip, info, score))
    ip_list.sort(key=lambda x: (-x[2], -x[1]['count']))

    print(f"{'IP':<40} {'总请求':>8} {'已拦截':>8} {'命中未拦':>10} {'可疑URL':>8} {'命中模块':>12}")
    for ip, info, _ in ip_list[:top_n]:
        print(f"{ip:<40} {info['count']:>8} {info['blocked']:>8} {info['not_blocked']:>10} "
              f"{info['suspicious']:>8} {','.join(sorted(info['rules'])) or '-':>12}")
        if info['suspicious_urls'] and not detail:
            sus_urls = list(info['suspicious_urls'])[:3]
            print(f"       可疑路径: {', '.join(sus_urls)}")
    print()

    if unknown_400:
        print("=" * 80)
        print(f"六、状态码 400 但未命中任何规则的请求: {len(unknown_400)} 条")
        print("=" * 80)
        for req in unknown_400[:top_n]:
            print(f"  [{req['status']}] {req['ip']} {req['method']} {req['uri'][:100]}")
            print(f"       UA: {req['ua'][:80]}")
        print()

    if detail and blocked:
        print("=" * 80)
        print(f"七、已拦截请求明细（前 {top_n} 条）")
        print("=" * 80)
        for req, hits in blocked[:top_n]:
            hit_desc = ' | '.join(f"{h[0]}" for h in hits)
            print(f"  [{req['status']}] {req['ip']} {req['method']} {req['uri'][:80]}")
            print(f"       UA: {req['ua'][:60]} 命中: {hit_desc}")
        print()


if __name__ == '__main__':
    main()
