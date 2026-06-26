#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分析 Nginx 访问日志，根据当前 WAF 规则判断哪些恶意/异常请求未被拦截。

判断逻辑：
1. 解析 access.log
2. 对每个请求模拟 WAF 检查（UA、Method、Dangerous、URL、Traversal）
3. 若请求命中任一 WAF 规则但状态码不是 WAF 拦截码（400/403/404/444/503），则视为“未被 WAF 阻挡”
4. 同时列出状态码为 200/301/308 等成功码的扫描/探测行为
"""

import re
import os
import sys
from urllib.parse import unquote

# 强制 UTF-8 输出，避免 Windows 终端乱码
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# IP 白名单（来自 config.lua）
IP_WHITELIST = {'127.0.0.1'}

LOG_FILE = "access.log"
WAFCF_DIR = "wafconf"

# WAF 拦截状态码集合
WAF_BLOCK_STATUSES = {400, 403, 404, 444, 503}


def parse_log_line(line):
    """解析单条 Nginx 访问日志"""
    # 处理请求首行可能是二进制转义序列的情况
    pattern = r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]*?)"\s+(\d{3})\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"\s*$'
    m = re.match(pattern, line)
    if not m:
        return None
    ip, time, request, status, size, referer, ua = m.groups()
    # 解析 method, uri, protocol
    # 兼容非标准请求行（如扫描器 / RAT 通信没有空格分隔 method 与 uri）
    req_parts = request.split(' ', 2)
    if len(req_parts) == 1:
        method = req_parts[0]
        uri_with_query = '/'
        protocol = ''
    else:
        method = req_parts[0]
        uri_with_query = req_parts[1] if len(req_parts) >= 2 else '/'
        protocol = req_parts[2] if len(req_parts) >= 3 else ''
    return {
        'ip': ip,
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
    """读取 wafconf 规则文件，返回规则列表"""
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
    """读取 dangerous 这类带 tag 的规则，返回 (rule, tag) 列表"""
    path = os.path.join(WAFCF_DIR, filename)
    rules = []
    current_tag = 'core'
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith('#'):
                # 从注释中提取 tag，如 #[aggressive]
                tag_match = re.match(r'^#\s*\[([^\]]+)\]', line)
                if tag_match:
                    current_tag = tag_match.group(1)
                continue
            rules.append((line, current_tag))
    return rules


def lua_re_match(text, pattern):
    """
    用 Python re 近似 Lua/PCRE 规则匹配。
    注意：Lua 正则与 PCRE 有差异，这里尽量兼容常见写法。
    """
    if text is None:
        return False
    text = str(text)
    # 一些简单替换：Lua 的 % 转义 -> Python 的 \ 转义
    pat = pattern.replace('%.', r'\.').replace('%2e', r'%2e').replace('%2E', r'%2E')
    # 保持原样，但把 Lua 的 \s 等已经兼容
    try:
        return re.search(pat, text, re.IGNORECASE) is not None
    except re.error as e:
        # 尝试修复不兼容写法
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
    """路径穿越检测"""
    # Lua: (\.\./|\.(%2e)|(%2e)\.|%2e%2e|%252e|\%00)
    pattern = r'(\.\./|\.(%2e)|(%2e)\.|%2e%2e|%252e|\%00)'
    if re.search(pattern, uri, re.IGNORECASE):
        return ('TRAVERSAL', pattern)
    return None


def is_scanner_or_probe(req):
    """启发式判断是否为扫描器/探测行为"""
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

    # POST / 根路径探测
    if method == 'POST' and uri == '/':
        return True

    # 非标准 HTTP 方法（ OPTIONS/HEAD 不算恶意）
    if method not in ('GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'PATCH', 'DELETE'):
        return True

    # 没有 UA 或 UA 异常短
    if req['ua'] == '-' or req['ua'] == 'Mozilla/5.0':
        # 结合路径判断，仅针对非静态资源
        if uri in ('/', '/version', '/v1', '/api/auth/validate-sso'):
            return True

    # 路径中包含编码后的特殊字符（如全角顿号 %E3%80%81）
    if '%' in req['uri'] and uri not in ('/',):
        decoded = unquote(req['uri'])
        if any(ord(c) > 127 for c in decoded):
            return True

    return False


def main():
    # 加载规则
    ua_rules = read_rules('user-agent')
    method_rules = read_rules('method')
    dangerous_rules = read_tagged_rules('dangerous')
    url_rules = read_rules('url')

    # 解析日志
    entries = []
    with open(LOG_FILE, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            if not line.strip():
                continue
            parsed = parse_log_line(line)
            if parsed:
                entries.append(parsed)
            else:
                print(f"[WARN] 无法解析: {line.strip()[:120]}")

    print(f"共解析 {len(entries)} 条日志")
    print(f"注：127.0.0.1 在 config.lua 的 ipWhitelist 中，WAF 对其直接放行\n")

    # 汇总
    blocked_by_waf = []
    not_blocked = []
    unknown_400 = []

    for req in entries:
        status = req['status']
        hits = []

        h = check_ua(req['ua'], ua_rules)
        if h:
            hits.append(h)
        h = check_method(req['method'], method_rules)
        if h:
            hits.append(h)
        h = check_dangerous(req['uri'], dangerous_rules)
        if h:
            hits.append(h)
        h = check_url(req['uri'], url_rules)
        if h:
            hits.append(h)
        h = check_traversal(req['uri'])
        if h:
            hits.append(h)

        if hits:
            if status in WAF_BLOCK_STATUSES:
                blocked_by_waf.append((req, hits))
            else:
                not_blocked.append((req, hits))
        else:
                    # 没有命中任何 WAF 规则，但状态码是 400 的异常请求
            if status == 400 and is_scanner_or_probe(req) and req['ip'] not in IP_WHITELIST:
                unknown_400.append(req)

    print("=" * 80)
    print(f"一、已确认被 WAF 拦截的请求（命中规则且状态码 {WAF_BLOCK_STATUSES}）: {len(blocked_by_waf)} 条")
    print("=" * 80)
    for req, hits in blocked_by_waf:
        hit_desc = ' | '.join([f"{h[0]}: {h[1][:60]}" for h in hits])
        print(f"  [{req['status']}] {req['ip']} {req['method']} {req['uri']}")
        print(f"       UA: {req['ua'][:80]}")
        print(f"       命中: {hit_desc}")
    print()

    print("=" * 80)
    print(f"二、命中 WAF 规则但未被拦截的请求（漏过）: {len(not_blocked)} 条")
    print("=" * 80)
    real_miss = []
    whitelist_miss = []
    for req, hits in not_blocked:
        if req['ip'] in IP_WHITELIST:
            whitelist_miss.append((req, hits))
        else:
            real_miss.append((req, hits))

    for req, hits in real_miss:
        hit_desc = ' | '.join([f"{h[0]}: {h[1][:60]}" for h in hits])
        print(f"  [{req['status']}] {req['ip']} {req['method']} {req['uri']}")
        print(f"       UA: {req['ua'][:80]}")
        print(f"       应命中: {hit_desc}")
    print()

    print(f"  （其中 {len(whitelist_miss)} 条来自白名单 IP 127.0.0.1，属于预期放行）")
    for req, hits in whitelist_miss[:3]:
        hit_desc = ' | '.join([f"{h[0]}: {h[1][:60]}" for h in hits])
        print(f"  ... [{req['status']}] {req['ip']} {req['method']} {req['uri']} 应命中 {hit_desc}")
    if len(whitelist_miss) > 3:
        print(f"  ... 还有 {len(whitelist_miss) - 3} 条白名单请求省略")
    print()

    print("=" * 80)
    print(f"三、状态码 400 但无法确认是否 WAF 拦截的异常请求: {len(unknown_400)} 条")
    print("=" * 80)
    for req in unknown_400:
        print(f"  [{req['status']}] {req['ip']} {req['method']} {req['uri']}")
        print(f"       UA: {req['ua'][:80]}")
    print()

    print("=" * 80)
    print("四、未命中 WAF 规则但属于扫描/探测行为的请求")
    print("=" * 80)
    count = 0
    for req in entries:
        if req['status'] in WAF_BLOCK_STATUSES:
            continue
        if is_scanner_or_probe(req):
            # 排除已经在 not_blocked 中的
            if req not in [x[0] for x in not_blocked]:
                count += 1
                print(f"  [{req['status']}] {req['ip']} {req['method']} {req['uri']}")
                print(f"       UA: {req['ua'][:80]}")
    print(f"   合计 {count} 条\n")


if __name__ == '__main__':
    main()
