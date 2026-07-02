local _M = {}

-- ============================================================
-- Worker 级规则缓存 + 正则预编译缓存
-- ============================================================
-- 设计要点：
-- 1. 使用 Lua 模块级局部表作为 Worker 缓存，无跨 worker 同步开销
-- 2. 纯 TTL 驱动刷新，避免 shell stat 子进程开销
-- 3. 正则表达式预编译并缓存，复用 PCRE 对象
-- 4. 非法正则会被记录并跳过，避免运行时抛错
-- 5. reload_all() 可强制清空缓存
-- ============================================================

-- 规则文件缓存
-- key = 规则文件路径
-- value = { rules = table, compiled = table, loaded_at = number, tagged = boolean }
local rule_cache = {}

-- 正则预编译缓存
-- key = pattern .. "\0" .. options
-- value = { ok = boolean, regex = compiled_regex }
local regex_cache = {}

-- 默认 TTL（秒），可通过 set_ttl 覆盖
local cache_ttl = 5

-- 统计信息
local stats = {
    rule_files = 0,
    tagged_rule_files = 0,
    regex_patterns = 0,
    regex_hits = 0,
    regex_misses = 0,
    cache_hits = 0,
    cache_misses = 0,
    invalid_rules = 0,
}

function _M.set_ttl(ttl)
    cache_ttl = tonumber(ttl) or 5
    if cache_ttl < 0 then
        cache_ttl = 0
    end
end

-- 校验并编译正则，返回编译后的 regex 对象或 nil
-- 在 ngx.re.compile 不可用环境（如 resty CLI）回退到 ngx.re.match 校验
local function compile_pattern(pattern, options)
    if not pattern or pattern == "" then
        return nil, "empty pattern"
    end
    options = options or "isj"

    if ngx.re.compile then
        local ok, regex_or_err = pcall(ngx.re.compile, pattern, options)
        if not ok then
            return nil, tostring(regex_or_err)
        end
        return regex_or_err
    end

    -- 回退：用空串做一次 match 校验语法
    local ok, err = pcall(ngx.re.match, "", pattern, options)
    if not ok then
        return nil, tostring(err)
    end
    -- 返回一个封装对象，复用 ngx.re.match
    return {
        match = function(self, text)
            return ngx.re.match(text, pattern, options)
        end
    }
end

-- 检查缓存是否过期
local function is_expired(cached)
    if cache_ttl == 0 then
        return true
    end
    return (ngx.now() - cached.loaded_at) >= cache_ttl
end

-- 读取规则文件（带缓存）
function _M.read_rule_cached(rulepath, var, force_reload)
    local filepath = rulepath .. var
    local now = ngx.now()
    local cached = rule_cache[filepath]

    if not force_reload and cached and not is_expired(cached) then
        stats.cache_hits = stats.cache_hits + 1
        return cached.rules
    end

    stats.cache_misses = stats.cache_misses + 1

    local file, err = io.open(filepath, "r")
    if not file then
        ngx.log(ngx.WARN, "WAF: failed to open rule file: ", filepath, " error: ", err or "unknown")
        return nil
    end

    local rules = {}
    local compiled = {}

    for line in file:lines() do
        line = string.gsub(line, "\r$", "")
        if line ~= "" and string.sub(line, 1, 1) ~= "#" then
            local regex, err = compile_pattern(line, "isj")
            if regex then
                table.insert(rules, line)
                table.insert(compiled, regex)
            else
                stats.invalid_rules = stats.invalid_rules + 1
                ngx.log(ngx.ERR, "WAF: invalid regex in ", filepath, ": ", line, " error: ", err)
            end
        end
    end
    file:close()

    rule_cache[filepath] = {
        rules = rules,
        compiled = compiled,
        loaded_at = now,
        tagged = false,
    }
    stats.rule_files = stats.rule_files + 1
    return rules
end

-- 读取带标记的规则文件（带缓存）
function _M.read_tagged_rule_cached(rulepath, var, force_reload)
    local filepath = rulepath .. var
    local now = ngx.now()
    local cached = rule_cache[filepath]

    if not force_reload and cached and not is_expired(cached) then
        stats.cache_hits = stats.cache_hits + 1
        return cached.rules
    end

    stats.cache_misses = stats.cache_misses + 1

    local file, err = io.open(filepath, "r")
    if not file then
        ngx.log(ngx.WARN, "WAF: failed to open tagged rule file: ", filepath, " error: ", err or "unknown")
        return nil
    end

    local rules = {}
    local compiled = {}
    local current_tag = "common"

    for line in file:lines() do
        line = string.gsub(line, "\r$", "")
        if line ~= "" then
            local tag = string.match(line, "^# %[(%w+)%]")
            if tag then
                current_tag = tag
            elseif string.sub(line, 1, 1) ~= "#" then
                local regex, err = compile_pattern(line, "isj")
                if regex then
                    table.insert(rules, { tag = current_tag, rule = line })
                    table.insert(compiled, { tag = current_tag, regex = regex })
                else
                    stats.invalid_rules = stats.invalid_rules + 1
                    ngx.log(ngx.ERR, "WAF: invalid regex in ", filepath, ": ", line, " error: ", err)
                end
            end
        end
    end
    file:close()

    rule_cache[filepath] = {
        rules = rules,
        compiled = compiled,
        loaded_at = now,
        tagged = true,
    }
    stats.tagged_rule_files = stats.tagged_rule_files + 1
    return rules
end

-- 带预编译缓存的正则匹配
function _M.match_cached(text, pattern, options)
    if not text or text == "" or not pattern or pattern == "" then
        return nil
    end

    options = options or "isj"
    local cache_key = pattern .. "\0" .. options
    local cached = regex_cache[cache_key]

    if cached then
        stats.regex_hits = stats.regex_hits + 1
        if not cached.ok then
            return nil
        end
        return cached.regex:match(text)
    end

    stats.regex_misses = stats.regex_misses + 1
    stats.regex_patterns = stats.regex_patterns + 1

    local regex, err = compile_pattern(pattern, options)
    if regex then
        regex_cache[cache_key] = { ok = true, regex = regex }
        return regex:match(text)
    else
        regex_cache[cache_key] = { ok = false }
        ngx.log(ngx.ERR, "WAF: regex compile failed: ", pattern, " error: ", err or "unknown")
        return nil
    end
end

-- 强制刷新所有缓存
function _M.reload_all()
    rule_cache = {}
    regex_cache = {}
    -- 重置命中/未命中计数（累计规则数、非法规则数保留）
    stats.cache_hits = 0
    stats.cache_misses = 0
    stats.regex_hits = 0
    stats.regex_misses = 0
    ngx.log(ngx.NOTICE, "WAF: rules cache reloaded")
    return true
end

-- 强制刷新单个规则文件
function _M.reload_file(rulepath, var)
    local filepath = rulepath .. var
    rule_cache[filepath] = nil
    ngx.log(ngx.NOTICE, "WAF: rule cache invalidated for ", filepath)
end

-- 获取统计信息
function _M.get_stats()
    return {
        rule_files = stats.rule_files,
        tagged_rule_files = stats.tagged_rule_files,
        regex_patterns = stats.regex_patterns,
        regex_hits = stats.regex_hits,
        regex_misses = stats.regex_misses,
        cache_hits = stats.cache_hits,
        cache_misses = stats.cache_misses,
        invalid_rules = stats.invalid_rules,
        ttl = cache_ttl,
    }
end

return _M
