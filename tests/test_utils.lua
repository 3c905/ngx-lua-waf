-- utils.lua 单元测试
-- 运行方式：resty tests/test_utils.lua

local utils = require "lib.utils"

local function assert_eq(a, b, msg)
    if a ~= b then
        error(string.format("%s: expected %s, got %s", msg or "assert_eq", tostring(b), tostring(a)))
    end
end

local function assert_true(v, msg)
    if not v then
        error(msg or "expected true")
    end
end

local function assert_false(v, msg)
    if v then
        error(msg or "expected false")
    end
end

-- 1. CIDR 测试
print("TEST: CIDR matching")
assert_true(utils.ip_in_cidr("192.168.1.1", "192.168.1.0/24"), "192.168.1.1 in 192.168.1.0/24")
assert_false(utils.ip_in_cidr("192.168.2.1", "192.168.1.0/24"), "192.168.2.1 not in 192.168.1.0/24")
assert_true(utils.ip_in_cidr("10.0.0.1", "10.0.0.0/8"), "10.0.0.1 in 10.0.0.0/8")
assert_true(utils.ip_in_cidr("127.0.0.1", "127.0.0.1"), "exact IP match")
assert_false(utils.ip_in_cidr("999.999.999.999", "10.0.0.0/8"), "invalid IP should not match")
print("PASS: CIDR matching")

-- 2. 解码链测试
print("TEST: decode_chain")
assert_eq(utils.decode_chain("%3Cscript%3E", 3), "<script>", "URL decode")
assert_eq(utils.decode_chain("%253Cscript%253E", 3), "<script>", "double URL decode")
assert_eq(utils.decode_chain("&lt;script&gt;", 3), "<script>", "HTML entity decode")
assert_eq(utils.decode_chain("\\x3cscript\\x3e", 3), "<script>", "hex decode")
print("PASS: decode_chain")

-- 3. IP 列表测试
print("TEST: ip_in_list")
utils.set_trusted_proxies({"10.0.0.0/8", "127.0.0.1"})
assert_true(utils.ip_in_list("10.1.2.3", {"10.0.0.0/8", "192.168.0.0/16"}), "IP in CIDR list")
assert_false(utils.ip_in_list("172.16.0.1", {"10.0.0.0/8", "192.168.0.0/16"}), "IP not in list")
print("PASS: ip_in_list")

-- 4. 请求分类测试
-- classify_request 依赖 ngx.var.uri / ngx.var.http_content_type，
-- 在 resty CLI 中不可用，需在 OpenResty HTTP 请求阶段测试。
print("TEST: classify_request")
print("INFO: classify_request requires HTTP request context, skipped in resty CLI")
print("PASS: classify_request (skipped)")

print("\nAll utils tests passed!")
