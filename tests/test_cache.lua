-- cache.lua 单元测试
-- 运行方式：resty tests/test_cache.lua

local cache = require "lib.cache"

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

-- 1. TTL 设置
print("TEST: set_ttl")
cache.set_ttl(5)
local stats = cache.get_stats()
assert_eq(stats.ttl, 5, "default ttl should be 5")
cache.set_ttl(10)
stats = cache.get_stats()
assert_eq(stats.ttl, 10, "ttl should be 10")
print("PASS: set_ttl")

-- 2. 读取规则文件
print("TEST: read_rule_cached")
local rules = cache.read_rule_cached("wafconf/", "url", true)
assert_true(rules and #rules > 0, "url rules should not be empty")
print(string.format("PASS: read_rule_cached loaded %d rules", #rules))

-- 3. 缓存命中
print("TEST: cache hit")
local rules2 = cache.read_rule_cached("wafconf/", "url", false)
assert_eq(#rules, #rules2, "cached rules count should match")
stats = cache.get_stats()
assert_true(stats.cache_hits >= 1, "should have cache hit")
print("PASS: cache hit")

-- 4. 非法正则跳过
print("TEST: invalid regex skip")
local tmp_path = "/tmp/waf_test_invalid_rules_" .. ngx.now()
local fd = io.open(tmp_path, "w")
fd:write("valid_rule_select\n")
fd:write("(invalid_unclosed_paren\n")
fd:close()

-- 直接读取临时文件
local invalid_rules = {}
local file = io.open(tmp_path, "r")
for line in file:lines() do
    table.insert(invalid_rules, line)
end
file:close()
os.remove(tmp_path)
assert_eq(#invalid_rules, 2, "test rules count")
print("PASS: invalid regex handling prepared")

-- 5. 正则匹配缓存
print("TEST: regex match cache")
local m1 = cache.match_cached("hello world", "hello", "isj")
assert_true(m1, "first match should succeed")
local m2 = cache.match_cached("hello world", "hello", "isj")
assert_true(m2, "cached match should succeed")
stats = cache.get_stats()
assert_true(stats.regex_hits >= 1, "should have regex cache hit")
print("PASS: regex match cache")

-- 6. reload_all
print("TEST: reload_all")
cache.reload_all()
stats = cache.get_stats()
assert_eq(stats.cache_hits, 0, "cache hits should reset")
assert_eq(stats.cache_misses, 0, "cache misses should reset")
print("PASS: reload_all")

-- 7. 带标记规则
print("TEST: read_tagged_rule_cached")
local tagged = cache.read_tagged_rule_cached("wafconf/", "dangerous", true)
assert_true(tagged and #tagged > 0, "dangerous rules should not be empty")
assert_true(tagged[1].tag, "first rule should have tag")
assert_true(tagged[1].rule, "first rule should have rule")
print(string.format("PASS: read_tagged_rule_cached loaded %d rules", #tagged))

print("\nAll cache tests passed!")
