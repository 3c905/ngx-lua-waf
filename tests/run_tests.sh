#!/bin/bash
# WAF Lua 单元测试运行脚本
# 依赖：OpenResty 的 resty 命令

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PROJECT_DIR=$(dirname "$SCRIPT_DIR")

cd "$PROJECT_DIR"

RESTY_BIN=${RESTY_BIN:-$(command -v resty 2>/dev/null)}
if [ -z "$RESTY_BIN" ] && [ -x /opt/homebrew/opt/openresty/bin/resty ]; then
    RESTY_BIN=/opt/homebrew/opt/openresty/bin/resty
fi
if [ -z "$RESTY_BIN" ] && [ -x /usr/local/openresty/bin/resty ]; then
    RESTY_BIN=/usr/local/openresty/bin/resty
fi
if [ -z "$RESTY_BIN" ]; then
    echo "Error: resty command not found"
    echo "Please install OpenResty and ensure resty is in PATH, or set RESTY_BIN"
    exit 1
fi

echo "Using resty: $RESTY_BIN"

echo "Running cache tests..."
"$RESTY_BIN" -I "$PROJECT_DIR" tests/test_cache.lua

echo ""
echo "Running utils tests..."
"$RESTY_BIN" -I "$PROJECT_DIR" tests/test_utils.lua

echo ""
echo "Validating rule files..."
python3 tests/validate_rules.py

echo ""
echo "All tests passed!"
