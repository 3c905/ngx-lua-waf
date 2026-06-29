#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""验证新增 CVE 规则能否匹配已知攻击 payload。"""
import re

HEADER_RULES = [
    ("CVE-2025-29927 x-middleware-subrequest", r"^x-middleware-subrequest:", "x-middleware-subrequest: middleware:middleware:middleware"),
    ("CVE-2025-29927 x-middleware-override-headers", r"^x-middleware-override-headers:", "x-middleware-override-headers: x-test"),
]

POST_RULES = [
    ("React2Shell status:resolved_model", r'"status"\s*:\s*"resolved_model"', '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1}'),
    ("React2Shell _response._prefix", r'"_response"\s*:\s*\{\s*"_prefix"', '{"_response":{"_prefix":"console.log(1)","_formData":{"get":"x"}}}'),
    ("React2Shell constructor:constructor", r'\$\d+:(?:constructor|__proto__):(?:constructor|then)', '"$1:constructor:constructor"'),
    ("React2Shell child_process", r'process\.mainModule\.require\s*\(\s*[\'"]child_process[\'"]\s*\)', "process.mainModule.require('child_process').execSync('id')"),
    ("React2Shell $@ marker", r'\$@\d+', '"$@0"'),
]


def test_rules(name, rules):
    print(f"\n[{name}]")
    all_ok = True
    for desc, pattern, sample in rules:
        try:
            pat = re.compile(pattern, re.IGNORECASE)
            matched = bool(pat.search(sample))
            status = "OK" if matched else "FAIL"
            if not matched:
                all_ok = False
            print(f"  [{status}] {desc}: {sample[:60]}")
        except re.error as e:
            all_ok = False
            print(f"  [ERROR] {desc}: {e}")
    return all_ok


if __name__ == "__main__":
    h_ok = test_rules("Header Rules (CVE-2025-29927)", HEADER_RULES)
    p_ok = test_rules("POST Body Rules (React2Shell / RSC)", POST_RULES)
    print("\n" + "=" * 50)
    if h_ok and p_ok:
        print("All CVE rule tests passed.")
    else:
        print("Some CVE rule tests failed.")
