#!/usr/bin/env python3
"""
校验 wafconf/ 下所有规则文件的正则语法。
注意：Python re 与 PCRE 不完全等价，但能捕获大部分语法错误（未闭合括号等）。
"""
import os
import re
from pathlib import Path

PROJECT_DIR = Path(__file__).parent.parent
RULE_DIR = PROJECT_DIR / "wafconf"


def validate_regex(pattern: str, source: str, line_no: int) -> bool:
    try:
        re.compile(pattern)
        return True
    except re.error as e:
        print(f"[INVALID] {source}:{line_no}: {pattern}")
        print(f"          error: {e}")
        return False


def validate_plain_file(filepath: Path) -> tuple[int, int]:
    """校验普通规则文件，返回 (有效规则数, 非法规则数)"""
    invalid = 0
    valid = 0
    with filepath.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.rstrip("\r\n")
            if not line or line.startswith("#"):
                continue
            if validate_regex(line, str(filepath), line_no):
                valid += 1
            else:
                invalid += 1
    return valid, invalid


def validate_tagged_file(filepath: Path) -> tuple[int, int]:
    """校验带标记的规则文件，返回 (有效规则数, 非法规则数)"""
    invalid = 0
    valid = 0
    current_tag = "common"
    with filepath.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.rstrip("\r\n")
            if not line:
                continue
            tag_match = re.match(r"^# \[(\w+)\]", line)
            if tag_match:
                current_tag = tag_match.group(1)
                continue
            if line.startswith("#"):
                continue
            if validate_regex(line, str(filepath), line_no):
                valid += 1
            else:
                invalid += 1
    return valid, invalid


def main():
    if not RULE_DIR.exists():
        print(f"Rule directory not found: {RULE_DIR}")
        return 1

    # 只校验实际会被 WAF 加载的规则文件
    rule_files = {
        "url", "args", "post", "cookie", "user-agent", "whiteurl",
        "header", "response", "dangerous", "referer", "method",
    }
    tagged_files = {"dangerous", "response"}
    total_valid = 0
    total_invalid = 0

    print(f"Validating rules in {RULE_DIR}")
    print("-" * 60)

    for filepath in sorted(RULE_DIR.iterdir()):
        if not filepath.is_file():
            continue
        name = filepath.name
        if name not in rule_files:
            continue
        if name in tagged_files:
            valid, invalid = validate_tagged_file(filepath)
        else:
            valid, invalid = validate_plain_file(filepath)
        total_valid += valid
        total_invalid += invalid
        status = "OK" if invalid == 0 else "FAIL"
        print(f"[{status}] {name:20s} valid={valid:3d} invalid={invalid:3d}")

    print("-" * 60)
    print(f"Total: valid={total_valid} invalid={total_invalid}")

    if total_invalid > 0:
        return 1
    return 0


if __name__ == "__main__":
    exit(main())
