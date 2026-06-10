local utils = require "utils"

local _M = {}

-- ============================================================
-- 增强版 CC 防御引擎
-- ============================================================
--
-- 核心改进：
-- 1. 请求分类：静态文件 / 动态请求 / API / 上传 差异化策略
-- 2. 三级计数：全局(IP) + 静态文件(IP) + 动态请求(IP+URI)
-- 3. Bot 信号联动：高风险 Bot 降低阈值
-- 4. 渐进式惩罚：503 → 302 挑战 → 临时封禁 → 长期封禁
-- 5. 静态文件专项：Referer/Cookie 验证，防盗链 CC

-- 共享字典名称（需在 nginx.conf 中配置）
local DICT_CC = "waf_cc"
local DICT_BAN = "waf_ban"

-- 默认配置（会被 config.lua 中的配置覆盖）
_M.config = {
    enabled = false,
    -- 全局全站限制
    global_rate = "2000/60",      -- 60秒内2000次（全站总计）
    
    -- 静态文件限制
    static_enabled = true,
    static_rate = "600/60",       -- 60秒内600次静态文件请求
    static_no_referer_rate = "200/60",   -- 无Referer静态请求更严格
    static_no_cookie_rate = "300/60",    -- 无Cookie静态请求更严格
    
    -- 动态请求限制
    dynamic_rate = "120/60",      -- 60秒内120次同URI请求
    api_rate = "300/60",          -- API接口稍宽松
    upload_rate = "30/60",        -- 上传限制更严格
    
    -- POST/写操作额外限制
    post_multiplier = 0.5,        -- POST请求阈值乘以0.5
    
    -- 渐进式惩罚
    progressive = true,
    ban_duration_1 = 60,          -- 第1次超限封禁60秒
    ban_duration_2 = 300,         -- 第2次封禁5分钟
    ban_duration_3 = 3600,        -- 第3次封禁1小时
    
    -- 挑战验证
    challenge_enabled = true,
    challenge_cookie = "_waf_cc",
    challenge_ttl = 300,
}

-- ============================================================
-- CC 动作模式辅助函数
-- ============================================================
local function cc_should_block()
    local sb = _G.should_block
    if sb then
        return sb("CCAction")
    end
    return true
end

local function cc_block_or_exit(status)
    if not cc_should_block() then
        return true
    end
    ngx.exit(status)
    return true
end

-- ============================================================
-- 辅助函数：解析 rate 字符串 "count/seconds"
-- ============================================================

local function parse_rate(rate_str)
    local count, seconds = string.match(rate_str, "^(%d+)%/(%d+)$")
    return tonumber(count) or 100, tonumber(seconds) or 60
end

-- ============================================================
-- 辅助函数：获取共享字典
-- ============================================================

local function get_dict(name)
    local dict = ngx.shared[name]
    if not dict then
        -- 降级到 limit（兼容旧配置）
        if name == DICT_CC then
            dict = ngx.shared.limit
        end
    end
    return dict
end

-- ============================================================
-- 检查 IP 是否已被封禁
-- ============================================================

function _M.is_banned(ip)
    local ban_dict = get_dict(DICT_BAN)
    if not ban_dict then
        return false
    end
    local banned, flags = ban_dict:get(ip)
    if banned then
        -- 返回封禁级别和剩余时间
        local ttl = ban_dict:ttl(ip) or 0
        return true, banned, ttl
    end
    return false
end

-- ============================================================
-- 封禁 IP
-- ============================================================

function _M.ban_ip(ip, level, duration)
    local ban_dict = get_dict(DICT_BAN)
    if not ban_dict then
        return
    end
    ban_dict:set(ip, level, duration)
    
    -- 日志记录
    local time = ngx.localtime()
    local msg = string.format("[CC-BAN] ip=%s level=%d duration=%ds time=%s\n", 
                              ip, level, duration, time)
    local logpath = logdir or "/tmp"
    local filename = logpath .. "/cc_ban.log"
    local fd = io.open(filename, "ab")
    if fd then
        fd:write(msg)
        fd:close()
    end
end

-- ============================================================
-- 执行 CC 计数检查（核心逻辑）
-- ============================================================

local function check_counter(dict, key, rate_str, bot_signals)
    if not dict then
        return false
    end
    
    local count_limit, window = parse_rate(rate_str)
    
    -- Bot 风险调整：高风险 Bot 阈值降低
    if bot_signals and bot_signals.risk_level == "high" then
        count_limit = math.floor(count_limit * 0.3)  -- 高风险降低70%
    elseif bot_signals and bot_signals.risk_level == "medium" then
        count_limit = math.floor(count_limit * 0.6)  -- 中风险降低40%
    end
    
    -- 最低阈值保护
    if count_limit < 5 then
        count_limit = 5
    end
    
    local current, err = dict:get(key)
    if current then
        if current >= count_limit then
            return true, current, count_limit
        else
            dict:incr(key, 1)
            return false, current + 1, count_limit
        end
    else
        dict:set(key, 1, window)
        return false, 1, count_limit
    end
end

-- ============================================================
-- 渐进式惩罚
-- ============================================================

local function apply_progressive_penalty(ip, uri, req_type)
    if not _M.config.progressive then
        return cc_block_or_exit(503)
    end
    
    local ban_dict = get_dict(DICT_BAN)
    local cc_dict = get_dict(DICT_CC)
    
    -- 查询该 IP 历史超限次数
    local history_key = "hist:" .. ip
    local history = 0
    if cc_dict then
        history = cc_dict:get(history_key) or 0
    end
    
    history = history + 1
    
    -- 设置/更新历史计数（较长窗口）
    if cc_dict then
        cc_dict:set(history_key, history, 3600)  -- 1小时窗口
    end
    
    -- 根据历史次数选择惩罚
    if history == 1 then
        -- 第1次：503 服务不可用
        return cc_block_or_exit(503)
        
    elseif history == 2 and _M.config.challenge_enabled then
        -- 第2次：尝试 Cookie 挑战
        local challenge_passed = ngx.var.cookie__waf_cc
        if challenge_passed and challenge_passed == "1" then
            -- 已通过挑战，但频率仍过高，封禁短时间
            _M.ban_ip(ip, 2, _M.config.ban_duration_1)
            return cc_block_or_exit(503)
        else
            -- 未通过挑战，设置 Cookie 要求验证
            if cc_should_block() then
                ngx.header["Set-Cookie"] = _M.config.challenge_cookie .. "=1; Path=/; Max-Age=" .. _M.config.challenge_ttl
                ngx.header["Content-Type"] = "text/html"
                ngx.status = 429
                ngx.say("<html><body>Too many requests. Please refresh.</body></html>")
            end
            return cc_block_or_exit(429)
        end
        
    elseif history == 3 then
        -- 第3次：临时封禁
        _M.ban_ip(ip, 3, _M.config.ban_duration_2)
        return cc_block_or_exit(503)
        
    else
        -- 第4次及以上：长期封禁
        _M.ban_ip(ip, 4, _M.config.ban_duration_3)
        return cc_block_or_exit(503)
    end
end

-- ============================================================
-- 主入口：执行 CC 检查
-- ============================================================

function _M.check()
    if not _M.config.enabled then
        return false
    end
    
    local ip = getClientIp and getClientIp() or utils.get_real_ip()
    local uri = ngx.var.uri or "/"
    local method = ngx.req.get_method() or "GET"
    local cc_dict = get_dict(DICT_CC)
    
    -- 0. 先检查是否已被封禁
    local banned, ban_level, ban_ttl = _M.is_banned(ip)
    if banned then
        if cc_should_block() then
            ngx.header["X-WAF-CC-Status"] = "banned"
            ngx.header["X-WAF-CC-TTL"] = tostring(ban_ttl)
        end
        return cc_block_or_exit(503)
    end
    
    -- 1. 获取 Bot 信号
    local bot = utils.bot_signals()
    
    -- 2. 请求分类
    local req_type = utils.classify_request()
    
    -- 3. 全局全站计数（所有请求都计入）
    local global_key = "global:" .. ip
    local global_hit, global_count, global_limit = check_counter(cc_dict, global_key, _M.config.global_rate, bot)
    if global_hit then
        -- 全站超限是最严重的，直接惩罚
        ngx.header["X-WAF-CC-Status"] = "global-limit"
        ngx.header["X-WAF-CC-Count"] = tostring(global_count)
        ngx.header["X-WAF-CC-Limit"] = tostring(global_limit)
        return apply_progressive_penalty(ip, uri, req_type)
    end
    
    -- 4. 按请求类型分类计数
    local type_rate
    local type_key
    
    if req_type == "static" then
        -- 静态文件策略
        if not _M.config.static_enabled then
            return false
        end
        
        type_rate = _M.config.static_rate
        type_key = "static:" .. ip
        
        -- 无 Referer 的静态请求更严格
        local referer = ngx.var.http_referer or ""
        if referer == "" then
            type_rate = _M.config.static_no_referer_rate
            type_key = "static_noref:" .. ip
        end
        
        -- 无 Cookie 也更严格
        local cookie = ngx.var.http_cookie or ""
        if cookie == "" then
            -- 取两个阈值中更严格的
            local noref_count = tonumber(string.match(_M.config.static_no_referer_rate, "^(%d+)")) or 200
            local nocookie_count = tonumber(string.match(_M.config.static_no_cookie_rate, "^(%d+)")) or 300
            if nocookie_count < noref_count then
                type_rate = _M.config.static_no_cookie_rate
                type_key = "static_nock:" .. ip
            end
        end
        
    elseif req_type == "api" then
        type_rate = _M.config.api_rate
        type_key = "api:" .. ip .. ":" .. uri
        
    elseif req_type == "upload" then
        type_rate = _M.config.upload_rate
        type_key = "upload:" .. ip
        
    else
        -- 动态请求
        type_rate = _M.config.dynamic_rate
        type_key = "dynamic:" .. ip .. ":" .. uri
    end
    
    -- POST 请求额外收紧
    if method == "POST" then
        local post_count = math.floor(tonumber(string.match(type_rate, "^(%d+)")) * _M.config.post_multiplier)
        type_rate = tostring(math.max(post_count, 5)) .. "/" .. string.match(type_rate, "/(%d+)$")
    end
    
    -- 执行分类计数
    local type_hit, type_count, type_limit = check_counter(cc_dict, type_key, type_rate, bot)
    if type_hit then
        ngx.header["X-WAF-CC-Status"] = req_type .. "-limit"
        ngx.header["X-WAF-CC-Count"] = tostring(type_count)
        ngx.header["X-WAF-CC-Limit"] = tostring(type_limit)
        return apply_progressive_penalty(ip, uri, req_type)
    end
    
    return false
end

-- ============================================================
-- 从旧配置迁移：兼容原版 denycc()
-- ============================================================

function _M.legacy_denycc()
    -- 如果增强 CC 未启用，回退到原版逻辑
    if not _M.config.enabled then
        -- 调用原版 denycc 逻辑（如果存在）
        if _G.denycc then
            return denycc()
        end
        return false
    end
    return _M.check()
end

-- ============================================================
-- 统计接口（调试用）
-- ============================================================

function _M.get_stats(ip)
    local cc_dict = get_dict(DICT_CC)
    if not cc_dict then
        return nil
    end
    
    ip = ip or (getClientIp and getClientIp() or utils.get_real_ip())
    
    local stats = {
        ip = ip,
        global = cc_dict:get("global:" .. ip) or 0,
        static = cc_dict:get("static:" .. ip) or 0,
        static_noref = cc_dict:get("static_noref:" .. ip) or 0,
        dynamic = cc_dict:get("dynamic:" .. ip .. ":" .. (ngx.var.uri or "/")) or 0,
        api = cc_dict:get("api:" .. ip .. ":" .. (ngx.var.uri or "/")) or 0,
        upload = cc_dict:get("upload:" .. ip) or 0,
        history = cc_dict:get("hist:" .. ip) or 0,
    }
    
    local banned, level, ttl = _M.is_banned(ip)
    stats.banned = banned
    stats.ban_level = level
    stats.ban_ttl = ttl
    
    return stats
end

-- ============================================================
-- 手动解除封禁
-- ============================================================

function _M.unban_ip(ip)
    local ban_dict = get_dict(DICT_BAN)
    local cc_dict = get_dict(DICT_CC)
    if not ban_dict or not cc_dict then
        return false, "shared dict not available"
    end
    
    if not ip or ip == "" then
        return false, "ip required"
    end
    
    -- 从封禁字典中删除
    ban_dict:delete(ip)
    
    -- 同时清理该 IP 的历史超限记录（可选，让其重新开始）
    cc_dict:delete("hist:" .. ip)
    
    -- 记录解除日志
    local time = ngx.localtime()
    local msg = string.format("[CC-UNBAN] ip=%s time=%s\n", ip, time)
    local logpath = logdir or "/tmp"
    local filename = logpath .. "/cc_ban.log"
    local fd = io.open(filename, "ab")
    if fd then
        fd:write(msg)
        fd:close()
    end
    
    return true
end

-- ============================================================
-- 获取当前封禁列表
-- ============================================================

function _M.get_ban_list()
    local ban_dict = get_dict(DICT_BAN)
    if not ban_dict then
        return nil, "shared dict not available"
    end
    
    local list = {}
    local keys = ban_dict:get_keys(0)  -- 0 = 获取所有 key
    
    for _, ip in ipairs(keys) do
        local level = ban_dict:get(ip)
        local ttl = ban_dict:ttl(ip) or 0
        if level then
            table.insert(list, {
                ip = ip,
                level = level,
                ttl = ttl,
                remain = math.max(0, math.floor(ttl))
            })
        end
    end
    
    return list
end

return _M
