#!/usr/bin/env python3
"""
使用 luaparser 检查项目所有 .lua 文件语法。
注意：luaparser 对 OpenResty 特有 API 不做语义检查，只检查语法结构。
"""
import sys
from pathlib import Path

try:
    from luaparser import ast
except ImportError:
    print("luaparser not installed. Run: pip install luaparser")
    sys.exit(1)

PROJECT_DIR = Path(__file__).parent.parent


def check_file(filepath: Path) -> bool:
    try:
        with filepath.open("r", encoding="utf-8") as f:
            source = f.read()
        ast.parse(source)
        print(f"[OK]   {filepath.relative_to(PROJECT_DIR)}")
        return True
    except Exception as e:
        print(f"[FAIL] {filepath.relative_to(PROJECT_DIR)}: {e}")
        return False


def main():
    lua_files = sorted(PROJECT_DIR.rglob("*.lua"))
    if not lua_files:
        print("No .lua files found")
        return 0

    failed = 0
    for filepath in lua_files:
        # 跳过 venv
        if ".venv" in filepath.parts:
            continue
        if not check_file(filepath):
            failed += 1

    print("-" * 60)
    print(f"Checked {len(lua_files)} files, {failed} failed")
    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
