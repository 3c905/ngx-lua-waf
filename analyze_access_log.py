#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分析 Nginx access log，判断当前 WAF 规则对攻击/恶意请求的覆盖情况。
"""
import re
import os
import sys
from collections import defaultdict
from urllib.parse import unquote

RULE_DIR = os.path.join(os.path.dirname(__file__), 'wafconf')

# 当前生效配置
CONFIG = {
    'BlockDangerous': True,
    'BlockAggressive': False,
    'BlockReferer': True,
    'BlockMethod': True,
    'BlockHeader': True,
    'BlockResponse': True,
    'UrlDeny': True,
    'CCDeny': True,
}

IP_WHITELIST = {"127.0.0.1"}
IP_BLOCKLIST = {"1.0.0.1", "162.216.150.244", "185.213.175.171"}
BLACK_FILEEXT = {"php", "jsp", "aspx", "py", "sh"}

# 常见浏览器/正常客户端 UA 关键词
BROWSER_UA_KEYWORDS = [
    'mozilla/5.0', 'mozilla/4.0', 'opera/', 'applewebkit', 'chrome/', 'safari/',
    'firefox/', 'edge/', 'trident/', 'msie ', 'dalvik/', 'okhttp'
]

# 可疑路径/模式（C2、扫描器、异常探测）
SUSPICIOUS_PATH_PATTERNS = [
    re.compile(r'^/[a-zA-Z0-9]{1,10}$'),         # 短随机路径如 /WuEL /a /mPlayer
    re.compile(r'/(?:SiteLoader|file\.ext|stager64)$', re.I),
    re.compile(r'^/json/serverinfo', re.I),
    re.compile(r'/%5fnext', re.I),               # 编码的 _next
    re.compile(r'/cgi-bin', re.I),
]

# 可疑 Referer
SUSPICIOUS_REFERER_KEYWORDS = ['cgi-bin', 'index2.asp']


def is_browser_ua(ua):
    ua_lower = ua.lower()
    return any(k in ua_lower for k in BROWSER_UA_KEYWORDS)


def is_likely_normal(rec):
    """判断是否为正常流量（浏览器访问首页/静态资源/h5）"""
    uri = rec['uri'].split('?')[0]
    ua = rec['ua']
    ref = rec['referer']

    if not is_browser_ua(ua):
        return False

    normal_paths = {'/', '/h5/', '/logo.png', '/robots.txt', '/sitemap.xml'}
    if uri in normal_paths:
        return True

    if uri.startswith('/_next/static/'):
        return True

    if ref.startswith('http://118.193.39.2/') or ref.startswith('https://118.193.39.2/'):
        return True

    return False


def is_suspicious_but_not_hit(rec):
    """判断未命中规则的请求是否仍然可疑"""
    uri = rec['uri']
    ua = rec['ua']
    ref = rec['referer']

    for pat in SUSPICIOUS_PATH_PATTERNS:
        if pat.search(uri):
            return True

    if ref != '-' and any(k in ref.lower() for k in SUSPICIOUS_REFERER_KEYWORDS):
        return True

    # 非浏览器 UA 且无其他规则命中
    if not is_browser_ua(ua) and ua != '-':
        return True

    # POST 到根路径
    if rec['method'] == 'POST' and uri == '/':
        return True

    return False


def load_plain_rules(name):
    rules = []
    path = os.path.join(RULE_DIR, name)
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            rules.append(line)
    return rules


def load_tagged_rules(name):
    rules = []
    path = os.path.join(RULE_DIR, name)
    current_tag = 'core'
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            raw = line.strip()
            if not raw or raw.startswith('#'):
                continue
            m = re.match(r'^\[(\w+)\]\s*$', raw)
            if m:
                current_tag = m.group(1)
                continue
            rules.append((current_tag, raw))
    return rules


def compile_rules(rules):
    compiled = []
    for r in rules:
        try:
            compiled.append((re.compile(r, re.IGNORECASE), r))
        except re.error as e:
            print(f"[WARN] 规则编译失败: {r[:80]}... err={e}", file=sys.stderr)
    return compiled


def parse_log_line(line):
    line = line.lstrip('- ')
    pattern = r'^(?P<ip>[\d\.a-fA-F:]+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>.*?)"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)\s+"(?P<referer>.*?)"\s+"(?P<ua>.*?)"'
    m = re.match(pattern, line)
    if not m:
        return None
    request = m.group('request')
    req_m = re.match(r'^(?P<method>\S+)\s+(?P<uri>\S+)(?:\s+(?P<proto>\S+))?$', request)
    if req_m:
        method = req_m.group('method')
        uri = req_m.group('uri')
        proto = req_m.group('proto') or ''
    else:
        method = request
        uri = ''
        proto = ''
    return {
        'ip': m.group('ip'),
        'time': m.group('time'),
        'request': request,
        'method': method,
        'uri': uri,
        'proto': proto,
        'status': int(m.group('status')),
        'size': m.group('size'),
        'referer': m.group('referer'),
        'ua': m.group('ua'),
        'raw': line.strip(),
    }


def ip_in_list(ip, lst):
    return ip in lst


def classify_status(status):
    if status in (403, 444, 503, 413, 431):
        return 'blocked'
    if status == 400:
        return 'nginx_reject'
    if status in (404, 301, 308, 200):
        return 'passed'
    return 'other'


def check_ua(ua, rules):
    for pat, orig in rules:
        if pat.search(ua):
            return ('UA', orig)
    return None


def check_method(method, rules):
    for pat, orig in rules:
        if pat.search(method):
            return ('METHOD', orig)
    return None


def check_traversal(uri):
    pat = re.compile(r'(\.\./|\.(%2e)|(%2e)\.|%2e%2e|%252e|%%32%65|\%00)', re.IGNORECASE)
    m = pat.search(uri)
    if m:
        return ('TRAVERSAL', m.group(0))
    return None


def check_url(uri, rules):
    for pat, orig in rules:
        if pat.search(uri):
            return ('URL', orig)
    return None


def check_dangerous(uri, rules):
    for tag, rule in rules:
        if tag == 'aggressive' and not CONFIG['BlockAggressive']:
            continue
        try:
            pat = re.compile(rule, re.IGNORECASE)
        except re.error:
            continue
        m = pat.search(uri)
        if m:
            return ('DANGEROUS', tag, rule, m.group(0))
    return None


def check_args(uri, rules):
    if '?' not in uri:
        return None
    qs = uri.split('?', 1)[1]
    pairs = re.split(r'[&;]', qs)
    values = []
    for p in pairs:
        if '=' in p:
            values.append(unquote(p.split('=', 1)[1]))
        else:
            values.append(unquote(p))
    for pat, orig in rules:
        for v in values:
            try:
                v2 = unquote(v)
            except Exception:
                v2 = v
            if pat.search(v) or pat.search(v2):
                return ('ARGS', orig, v[:80])
    return None


def check_referer(ref, rules):
    for pat, orig in rules:
        if pat.search(ref):
            return ('REFERER', orig)
    return None


def check_whiteurl(uri, rules):
    for pat, _ in rules:
        if pat.search(uri):
            return True
    return False


def check_fileext(uri):
    m = re.search(r'\.([a-zA-Z0-9]+)$', uri.split('?')[0], re.IGNORECASE)
    if m and m.group(1).lower() in BLACK_FILEEXT:
        return ('FILEEXT', m.group(1))
    return None


def analyze(log_path):
    ua_rules = compile_rules(load_plain_rules('user-agent'))
    method_rules = compile_rules(load_plain_rules('method'))
    url_rules = compile_rules(load_plain_rules('url'))
    referer_rules = compile_rules(load_plain_rules('referer'))
    args_rules = compile_rules(load_plain_rules('args'))
    whiteurl_rules = compile_rules(load_plain_rules('whiteurl'))
    dangerous_rules = load_tagged_rules('dangerous')

    results = []
    stats = {
        'total': 0,
        'blocked_by_nginx': 0,
        'blocked_by_waf_in_log': 0,
        'would_be_blocked_by_rules': 0,
        'normal': 0,
        'suspicious_missed': 0,
        'unknown': 0,
    }

    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = parse_log_line(line)
            if not rec:
                stats['unknown'] += 1
                continue

            stats['total'] += 1
            status_class = classify_status(rec['status'])

            if ip_in_list(rec['ip'], IP_WHITELIST):
                results.append((rec, 'WHITELIST', None))
                stats['normal'] += 1
                continue

            if ip_in_list(rec['ip'], IP_BLOCKLIST):
                results.append((rec, 'IPBLOCK', None))
                stats['would_be_blocked_by_rules'] += 1
                continue

            hit = None

            if not hit and CONFIG['BlockMethod']:
                hit = check_method(rec['method'], method_rules)

            if not hit and rec['uri']:
                hit = check_traversal(rec['uri'])

            is_white = False
            if not hit and rec['uri']:
                is_white = check_whiteurl(rec['uri'].split('?')[0], whiteurl_rules)

            if not hit and CONFIG['BlockReferer'] and rec['referer'] != '-':
                hit = check_referer(rec['referer'], referer_rules)

            if not hit and rec['ua'] and rec['ua'] != '-':
                hit = check_ua(rec['ua'], ua_rules)

            if not hit and CONFIG['BlockDangerous'] and rec['uri']:
                hit = check_dangerous(rec['uri'], dangerous_rules)

            if not hit and CONFIG['UrlDeny'] and rec['uri']:
                hit = check_url(rec['uri'], url_rules)

            if not hit and rec['uri']:
                hit = check_args(rec['uri'], args_rules)

            if not hit and rec['uri']:
                hit = check_fileext(rec['uri'])

            if hit:
                results.append((rec, 'RULE_HIT', hit))
                stats['would_be_blocked_by_rules'] += 1
            else:
                if status_class == 'blocked':
                    results.append((rec, 'BLOCKED_NO_RULE', None))
                    stats['blocked_by_waf_in_log'] += 1
                elif status_class == 'nginx_reject':
                    results.append((rec, 'NGINX_REJECT', None))
                    stats['blocked_by_nginx'] += 1
                elif is_white:
                    results.append((rec, 'WHITEURL', None))
                    stats['normal'] += 1
                elif is_likely_normal(rec):
                    results.append((rec, 'NORMAL_TRAFFIC', None))
                    stats['normal'] += 1
                elif is_suspicious_but_not_hit(rec):
                    results.append((rec, 'SUSPICIOUS_MISS', None))
                    stats['suspicious_missed'] += 1
                else:
                    results.append((rec, 'UNKNOWN', None))
                    stats['normal'] += 1  # 默认归为正常

    return results, stats


def classify_attack_type(rec, detail):
    module = detail[0]
    if module == 'UA':
        ua = rec['ua'].lower()
        if 'palo' in ua or 'xpanse' in ua:
            return 'PaloAlto/Cortex 扫描'
        elif 'zgrab' in ua:
            return 'zgrab 扫描'
        elif 'shodan' in ua:
            return 'Shodan 扫描'
        elif 'masscan' in ua or 'ivre' in ua:
            return 'masscan 扫描'
        elif 'libredtail' in ua:
            return 'libredtail 扫描'
        elif 'go-http-client' in ua:
            return 'Go-http-client 探测'
        elif 'curl' in ua:
            return 'curl 探测'
        elif 'umai' in ua:
            return 'Umai 扫描'
        elif 'modat' in ua:
            return 'Modat 扫描'
        elif 'freepbx' in ua:
            return 'FreePBX 扫描'
        else:
            return 'UA黑名单(其他)'
    elif module == 'METHOD':
        return '危险HTTP方法/非标准协议'
    elif module == 'TRAVERSAL':
        return '路径穿越'
    elif module == 'DANGEROUS':
        tag = detail[1]
        uri = rec['uri'].lower()
        if 'phpunit' in uri:
            return 'CVE-2017-9841 PHPUnit RCE'
        elif 'jolokia' in uri:
            return 'Jolokia 敏感端点'
        elif 'actuator' in uri:
            return 'Spring Boot Actuator 探测'
        elif 'autodiscover' in uri:
            return 'Exchange Autodiscover SSRF'
        elif '.env' in uri:
            return '.env 配置文件泄露探测'
        elif 'vendor' in uri:
            return 'vendor 目录探测'
        elif 'thinkphp' in uri or 's=/index' in uri:
            return 'ThinkPHP RCE'
        elif 'containers/json' in uri:
            return 'Docker API 探测'
        elif 'version' in uri:
            return '/version 版本探测'
        elif 'manager/html' in uri:
            return 'Tomcat 管理后台探测'
        elif 'json/serverinfo' in uri:
            return 'Node 调试接口探测'
        elif '/_profiler' in uri:
            return 'Symfony Profiler 探测'
        elif tag == 'core':
            return 'DANGEROUS[core]'
        else:
            return f'DANGEROUS[{tag}]'
    elif module == 'URL':
        return 'URL黑名单'
    elif module == 'ARGS':
        return 'GET参数攻击'
    elif module == 'REFERER':
        return '恶意Referer'
    elif module == 'FILEEXT':
        return '文件扩展名黑名单'
    return module


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else r'D:\lumin\desktop\www.alcon.cn.log'
    results, stats = analyze(log_path)

    out_lines = []
    out_lines.append("=" * 80)
    out_lines.append(f"日志分析结果: {log_path}")
    out_lines.append("=" * 80)
    out_lines.append(f"总请求数: {stats['total']}")
    out_lines.append(f"  - 正常/白名单: {stats['normal']}")
    out_lines.append(f"  - 已被规则覆盖（将拦截）: {stats['would_be_blocked_by_rules']}")
    out_lines.append(f"  - 日志中已显示被拦截但规则未命中: {stats['blocked_by_waf_in_log']}")
    out_lines.append(f"  - Nginx 层直接拒绝（畸形/TLS/空请求）: {stats['blocked_by_nginx']}")
    out_lines.append(f"  - 疑似漏网（可疑但未命中规则）: {stats['suspicious_missed']}")
    out_lines.append(f"  - 无法解析: {stats['unknown']}")
    out_lines.append("")

    module_hits = defaultdict(int)
    suspicious_samples = []
    blocked_no_rule_samples = []
    nginx_reject_samples = []

    for rec, reason, detail in results:
        if reason == 'RULE_HIT':
            module = detail[0]
            module_hits[module] += 1
        elif reason == 'SUSPICIOUS_MISS':
            suspicious_samples.append(rec)
        elif reason == 'BLOCKED_NO_RULE':
            blocked_no_rule_samples.append(rec)
        elif reason == 'NGINX_REJECT':
            nginx_reject_samples.append(rec)

    out_lines.append("[规则命中模块分布]")
    for mod, cnt in sorted(module_hits.items(), key=lambda x: -x[1]):
        out_lines.append(f"  {mod}: {cnt}")
    out_lines.append("")

    out_lines.append(f"[Nginx 层直接拒绝的示例] (共 {len(nginx_reject_samples)} 条)")
    for rec in nginx_reject_samples[:10]:
        out_lines.append(f"  {rec['ip']} | {rec['method'][:40]} | {rec['status']} | UA={rec['ua'][:50]}")
    out_lines.append("")

    out_lines.append(f"[日志显示已拦截但规则未命中] (共 {len(blocked_no_rule_samples)} 条，可能是 CC/Response/POST/人工封禁)")
    for rec in blocked_no_rule_samples[:15]:
        out_lines.append(f"  {rec['ip']} | {rec['method'][:40]} | {rec['uri'][:80]} | {rec['status']} | UA={rec['ua'][:50]}")
    out_lines.append("")

    out_lines.append(f"[疑似漏网请求] (共 {len(suspicious_samples)} 条)")
    for rec in suspicious_samples:
        out_lines.append(f"  {rec['ip']} | {rec['method'][:40]} | {rec['uri'][:80]} | {rec['status']} | UA={rec['ua'][:60]} | Ref={rec['referer'][:40]}")
    out_lines.append("")

    attack_types = defaultdict(list)
    for rec, reason, detail in results:
        if reason != 'RULE_HIT':
            continue
        atype = classify_attack_type(rec, detail)
        attack_types[atype].append(rec)

    out_lines.append("[按攻击类型汇总]")
    for atype, lst in sorted(attack_types.items(), key=lambda x: -len(x[1])):
        out_lines.append(f"  {atype}: {len(lst)}")
    out_lines.append("")

    out_lines.append("[结论]")
    if stats['suspicious_missed'] == 0:
        out_lines.append("  当前规则可覆盖日志中所有明显的攻击/恶意请求。")
    else:
        out_lines.append(f"  发现 {stats['suspicious_missed']} 条请求状态码非拦截且未命中规则，需进一步确认是否为攻击或正常业务。")

    output = '\n'.join(out_lines)

    # 同时输出到文件（UTF-8）和标准输出
    out_file = os.path.join(os.path.dirname(__file__), 'analyze_access_log_result.txt')
    with open(out_file, 'w', encoding='utf-8') as f:
        f.write(output + '\n')

    # 使用 UTF-8 编码输出
    sys.stdout.reconfigure(encoding='utf-8')
    print(output)
    print(f"\n[结果已保存到: {out_file}]")


if __name__ == '__main__':
    main()
