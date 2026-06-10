local _M = {}

-- ============================================================
-- 规则缓存与正则预编译缓存
-- ============================================================
-- 
-- 设计目标：
-- 1. 每个 worker 独立缓存，避免 shared dict 的序列化开销和锁竞争
-- 2. 支持规则热更新（基于 TTL 自动刷新）
-- 3. 正则表达式预编译缓存，减少重复编译开销
--
-- 注意：由于是 worker-level 缓存，热更新最多延迟 TTL 秒
--       如需立即生效，可调用 reload_all() 或调整 TTL

local CACHE_TTL = 5  -- 默认缓存 5 秒
local rule_cache = {}       -- { [filepath] = { data=..., time=... } }
local tagged_rule_cache = {} -- { [filepath] = { data=..., time=... } }
local regex_cache = {}      -- { [pattern] = { compiled=..., time=... } }

-- 设置全局 TTL（可在 config.lua 中覆盖）
function _M.set_ttl(ttl)
    CACHE_TTL = tonumber(ttl) or 5
end

-- ============================================================
-- 规则读取（带缓存的普通规则）
-- ============================================================

function _M.read_rule_cached(rulepath, var, force_reload)
    local filepath = rulepath .. var
    local now = ngx.now()
    local cached = rule_cache[filepath]
    
    -- 缓存有效且非强制刷新
    if not force_reload and cached and (now - cached.time) < CACHE_TTL then
        return cached.data
    end
    
    -- 重新读取文件
    local file, err = io.open(filepath, "r")
    if not file then
        ngx.log(ngx.WARN, "WAF: failed to open rule file: ", filepath, " error: ", err or "unknown")
        return nil
    end
    
    local t = {}
    for line in file:lines() do
        if line ~= "" and string.sub(line, 1, 1) ~= "#" then
            table.insert(t, line)
        end
    end
    file:close()
    
    rule_cache[filepath] = { data = t, time = now }
    return t
end

-- ============================================================
-- 规则读取（带缓存的标记规则，如 dangerous）
-- ============================================================

function _M.read_tagged_rule_cached(rulepath, var, force_reload)
    local filepath = rulepath .. var
    local now = ngx.now()
    local cached = tagged_rule_cache[filepath]
    
    if not force_reload and cached and (now - cached.time) < CACHE_TTL then
        return cached.data
    end
    
    local file, err = io.open(filepath, "r")
    if not file then
        ngx.log(ngx.WARN, "WAF: failed to open tagged rule file: ", filepath, " error: ", err or "unknown")
        return nil
    end
    
    local t = {}
    local current_tag = "common"
    for line in file:lines() do
        if line ~= "" then
            local tag = string.match(line, "^# %[(\w+)%]")
            if tag then
                current_tag = tag
            elseif string.sub(line, 1, 1) ~= "#" then
                table.insert(t, { tag = current_tag, rule = line })
            end
        end
    end
    file:close()
    
    tagged_rule_cache[filepath] = { data = t, time = now }
    return t
end

-- ============================================================
-- 正则预编译缓存
-- ============================================================

function _M.match_cached(text, pattern, options)
    if not text or text == "" then
        return nil
    end
    if not pattern or pattern == "" then
        return nil
    end
    
    options = options or "isjo"
    local cache_key = pattern .. string.char(0) .. options
    local now = ngx.now()
    local cached = regex_cache[cache_key]
    
    -- 检查缓存（正则编译结果在 worker 间可复用，理论上不会变，但仍设 TTL）
    if cached and (now - cached.time) < 3600 then  -- 正则缓存 1 小时
        -- 使用已编译的正则执行匹配
        return ngx.re.match(text, pattern, options)
    end
    
    -- 首次编译并缓存（ngx.re.match 内部会编译，但我们只记录"已尝试编译"）
    -- 实际上 ngx.re.match 有内部缓存（PCRE JIT），这里主要是记录模式存在性
    local result = ngx.re.match(text, pattern, options)
    regex_cache[cache_key] = { time = now }
    return result
end

-- ============================================================
-- 强制刷新所有缓存（热更新接口用）
-- ============================================================

function _M.reload_all()
    rule_cache = {}
    tagged_rule_cache = {}
    regex_cache = {}
    ngx.log(ngx.NOTICE, "WAF: all rule caches purged")
end

-- 刷新指定规则文件
function _M.reload_file(rulepath, var)
    local filepath = rulepath .. var
    rule_cache[filepath] = nil
    tagged_rule_cache[filepath] = nil
    -- 重新加载
    _M.read_rule_cached(rulepath, var, true)
    _M.read_tagged_rule_cached(rulepath, var, true)
end

-- ============================================================
-- 缓存状态查询（调试用）
-- ============================================================

function _M.get_stats()
    local stats = {
        rule_files = 0,
        tagged_rule_files = 0,
        regex_patterns = 0,
        ttl = CACHE_TTL,
    }
    for _ in pairs(rule_cache) do stats.rule_files = stats.rule_files + 1 end
    for _ in pairs(tagged_rule_cache) do stats.tagged_rule_files = stats.tagged_rule_files + 1 end
    for _ in pairs(regex_cache) do stats.regex_patterns = stats.regex_patterns + 1 end
    return stats
end

return _M
