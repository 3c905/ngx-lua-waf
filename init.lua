require 'config'
local match = string.match
local ngxmatch = ngx.re.match
local unescape = ngx.unescape_uri
local get_headers = ngx.req.get_headers
local optionIsOn = function(options) return options == "on" and true or false end

-- ============================================================
-- 加载增强库
-- ============================================================
local cache = require "cache"
local utils = require "utils"

-- 设置缓存 TTL
if RuleCacheTTL then
    cache.set_ttl(RuleCacheTTL)
end

-- 设置信任代理
if TrustedProxies then
    utils.set_trusted_proxies(TrustedProxies)
end

-- 加载增强 CC 模块（如果启用）
local cc_enhanced
if optionIsOn(CCEnhanced) then
    cc_enhanced = require "cc_enhanced"
    cc_enhanced.config.enabled = true
    cc_enhanced.config.global_rate = CCGlobalRate or "2000/60"
    cc_enhanced.config.static_enabled = optionIsOn(CCStaticEnabled)
    cc_enhanced.config.static_rate = CCStaticRate or "600/60"
    cc_enhanced.config.static_no_referer_rate = CCStaticNoRefererRate or "200/60"
    cc_enhanced.config.static_no_cookie_rate = CCStaticNoCookieRate or "300/60"
    cc_enhanced.config.dynamic_rate = CCDynamicRate or "120/60"
    cc_enhanced.config.api_rate = CCApiRate or "300/60"
    cc_enhanced.config.upload_rate = CCUploadRate or "30/60"
    cc_enhanced.config.post_multiplier = CCPostMultiplier or 0.5
    cc_enhanced.config.progressive = optionIsOn(CCProgressive)
    cc_enhanced.config.ban_duration_1 = CCBanDuration1 or 60
    cc_enhanced.config.ban_duration_2 = CCBanDuration2 or 300
    cc_enhanced.config.ban_duration_3 = CCBanDuration3 or 3600
    cc_enhanced.config.challenge_enabled = optionIsOn(CCChallengeEnabled)
    cc_enhanced.config.challenge_cookie = CCChallengeCookie or "_waf_cc"
    cc_enhanced.config.challenge_ttl = CCChallengeTTL or 300
end

-- ============================================================
-- 全局配置变量（保持向后兼容）
-- ============================================================
logpath = logdir and string.gsub(logdir, "\r$", "") or "/tmp"
rulepath = RulePath and string.gsub(RulePath, "\r$", "") or "/tmp/"
UrlDeny = optionIsOn(UrlDeny)
PostCheck = optionIsOn(postMatch)
CookieCheck = optionIsOn(cookieMatch)
WhiteCheck = optionIsOn(whiteModule)
PathInfoFix = optionIsOn(PathInfoFix)
attacklog = optionIsOn(attacklog)
CCDeny = optionIsOn(CCDeny)
Redirect = optionIsOn(Redirect)
BlockDangerousCheck = optionIsOn(BlockDangerous)
BlockAggressiveCheck = optionIsOn(BlockAggressive)
BlockRefererCheck = optionIsOn(BlockReferer)
BlockMethodCheck = optionIsOn(BlockMethod)
BlockHeaderCheck = optionIsOn(BlockHeader)
BlockResponseCheck = optionIsOn(BlockResponse)

-- 日志限流配置
LogRateLimit = LogRateLimit or 0

-- ============================================================
-- 日志限流表（worker 级别）
-- ============================================================
local log_limiter = {}

-- multipart 文件上传状态标志（waf.lua 使用）
filetranslate = false

-- ============================================================
-- IP 获取（支持 XFF）
-- ============================================================

function getClientIp()
    -- 优先使用 utils 的 XFF 解析
    local ip = utils.get_real_ip()
    if ip and ip ~= "" and ip ~= "unknown" then
        return ip
    end
    -- 降级到 remote_addr
    local IP = ngx.var.remote_addr 
    if IP == nil then
        IP = "unknown"
    end
    return IP
end

-- ============================================================
-- 日志写入（带限流）
-- ============================================================

function write(logfile, msg)
    local fd, err = io.open(logfile, "ab")
    if fd == nil then
        ngx.log(ngx.ERR, "WAF write() failed to open ", logfile, ": ", tostring(err))
        return
    end
    fd:write(msg)
    fd:flush()
    fd:close()
end

function log(method, url, data, ruletag)
    if not attacklog then
        return
    end
    
    local realIp = getClientIp()
    local ua = ngx.var.http_user_agent
    local servername = ngx.var.server_name
    local time = ngx.localtime()
    local filename = logpath .. "/" .. servername .. "_" .. ngx.today() .. "_sec.log"
    ngx.log(ngx.ERR, "WAF_LOG: filename=", filename)
    
    -- 日志限流检查
    if LogRateLimit and LogRateLimit > 0 then
        local limit_key = realIp .. ":" .. ruletag
        local now = math.floor(ngx.now())
        local window = math.floor(now / 60)  -- 60 秒窗口
        local window_key = limit_key .. ":" .. window
        
        local current = log_limiter[window_key] or 0
        if current >= LogRateLimit then
            return  -- 超过限流阈值，丢弃日志
        end
        log_limiter[window_key] = current + 1
        
        -- 清理旧窗口（简单 GC）
        if math.random(1, 100) == 1 then
            local old_window = window - 2
            for k, _ in pairs(log_limiter) do
                if string.find(k, ":" .. old_window, 1, true) then
                    log_limiter[k] = nil
                end
            end
        end
    end
    
    local line
    if ua then
        line = realIp .. " [" .. time .. "] \"" .. method .. " " .. servername .. url .. "\" \"" .. (data or "-") .. "\"  \"" .. ua .. "\" \"" .. ruletag .. "\"\n"
    else
        line = realIp .. " [" .. time .. "] \"" .. method .. " " .. servername .. url .. "\" \"" .. (data or "-") .. "\" - \"" .. ruletag .. "\"\n"
    end
    local filename = logpath .. '/' .. servername .. "_" .. ngx.today() .. "_sec.log"
    write(filename, line)
end

-- ============================================================
-- 规则读取（带缓存）
-- ============================================================

function read_rule(var)
    return cache.read_rule_cached(rulepath, var, false)
end

function read_tagged_rule(var)
    return cache.read_tagged_rule_cached(rulepath, var, false)
end

-- ============================================================
-- 加载规则（使用缓存）
-- ============================================================
urlrules = read_rule('url')
argsrules = read_rule('args')
uarules = read_rule('user-agent')
wturlrules = read_rule('whiteurl')
postrules = read_rule('post')
ckrules = read_rule('cookie')
dgrules = read_tagged_rule('dangerous')
refererrules = read_rule('referer')
methodrules = read_rule('method')
headerrules = read_rule('header')
responserules = read_rule('response')

-- ============================================================
-- 动作模式判断：是否拦截
-- action_key: 对应 config.lua 中的 xxxAction 变量名
-- 返回 true 表示需要拦截，false 表示仅记录日志
-- ============================================================
function should_block(action_key)
    if action_key and _G[action_key] then
        return _G[action_key] == "block"
    end
    if ActionMode then
        return ActionMode == "block"
    end
    return true
end

-- ============================================================
-- 响应处理
-- ============================================================

function say_html(status)
    ngx.header.content_type = "text/html"
    ngx.status = status or ngx.HTTP_FORBIDDEN
    if Redirect then
        ngx.say(html)
    end
    return ngx.exit(ngx.status)
end

-- ============================================================
-- URL 白名单
-- ============================================================

function whiteurl()
    if WhiteCheck then
        if wturlrules ~= nil then
            for _, rule in pairs(wturlrules) do
                if cache.match_cached(ngx.var.uri, rule, "isj") then
                    return true 
                end
            end
        end
    end
    return false
end

-- ============================================================
-- 文件扩展名检查
-- ============================================================

function fileExtCheck(ext)
    local items = Set(black_fileExt)
    ext = string.lower(ext)
    if ext then
        for rule in pairs(items) do
            if cache.match_cached(ext, rule, "isj") then
                log('POST', ngx.var.request_uri, "-", "[FILEEXT][403] hit=[" .. ext .. "] rule=" .. rule)
                if should_block("FileExtAction") then
                    return say_html()
                end
                return true
            end
        end
    end
    return false
end

function Set(list)
    local set = {}
    for _, l in ipairs(list) do set[l] = true end
    return set
end

-- ============================================================
-- GET 参数检查（增强：多重解码）
-- ============================================================

function args()
    for _, rule in pairs(argsrules or {}) do
        local args = ngx.req.get_uri_args()
        for key, val in pairs(args) do
            if type(val) == 'table' then
                local t = {}
                for k, v in pairs(val) do
                    if v == true then
                        v = ""
                    end
                    table.insert(t, v)
                end
                local data = table.concat(t, " ")
            else
                local data = val
            end
            if data and type(data) ~= "boolean" and rule ~= "" then
                -- 使用解码链防御编码绕过
                local decoded = utils.decode_chain(unescape(data), 3)
                local m = cache.match_cached(decoded, rule, "isj")
                if not m then
                    -- 再检查原始值
                    m = cache.match_cached(unescape(data), rule, "isj")
                end
                if m then
                    log('GET', ngx.var.request_uri, "-", "[ARGS][403] hit=[" .. string.sub(m[0] or "-", 1, 200) .. "] rule=" .. rule)
                    if should_block("ArgsAction") then
                        return say_html()
                    end
                    return true
                end
            end
        end
    end
    return false
end

-- ============================================================
-- URL 黑名单
-- ============================================================

function url()
    if UrlDeny then
        for _, rule in pairs(urlrules or {}) do
            if rule ~= "" then
                local m = cache.match_cached(ngx.var.request_uri, rule, "isj")
                if m then
                    log('GET', ngx.var.request_uri, "-", "[URL][403] hit=[" .. string.sub(m[0] or "-", 1, 200) .. "] rule=" .. rule)
                    if should_block("URLAction") then
                        return say_html()
                    end
                    return true
                end
            end
        end
    end
    return false
end

-- ============================================================
-- User-Agent 检查
-- ============================================================

function ua()
    local ua = ngx.var.http_user_agent
    if ua ~= nil then
        for _, rule in pairs(uarules or {}) do
            if rule ~= "" then
                local m = cache.match_cached(ua, rule, "isj")
                if m then
                    log('UA', ngx.var.request_uri, "-", "[UA][403] hit=[" .. string.sub(m[0] or "-", 1, 200) .. "] rule=" .. rule)
                    if should_block("UAAction") then
                        return say_html()
                    end
                    return true
                end
            end
        end
    end
    return false
end

-- ============================================================
-- POST 参数检查（增强：多重解码）
-- ============================================================

function body(data)
    for _, rule in pairs(postrules or {}) do
        if rule ~= "" and data ~= "" then
            local decoded = utils.decode_chain(unescape(data), 3)
            local m = cache.match_cached(decoded, rule, "isj")
            if not m then
                m = cache.match_cached(unescape(data), rule, "isj")
            end
            if m then
                log('POST', ngx.var.request_uri, data, "[POST][403] hit=[" .. string.sub(m[0] or "-", 1, 200) .. "] rule=" .. rule)
                if should_block("PostAction") then
                    return say_html()
                end
                return true
            end
        end
    end
    return false
end

-- ============================================================
-- Cookie 检查
-- ============================================================

function cookie()
    local ck = ngx.var.http_cookie
    if CookieCheck and ck then
        for _, rule in pairs(ckrules or {}) do
            if rule ~= "" then
                local m = cache.match_cached(ck, rule, "isj")
                if m then
                    log('Cookie', ngx.var.request_uri, "-", "[COOKIE][403] hit=[" .. string.sub(m[0] or "-", 1, 200) .. "] rule=" .. rule)
                    if should_block("CookieAction") then
                        return say_html()
                    end
                    return true
                end
            end
        end
    end
    return false
end

-- ============================================================
-- CC 防御（兼容旧版 + 增强版）
-- ============================================================

function denycc()
    -- 优先使用增强版 CC
    if cc_enhanced and cc_enhanced.config.enabled then
        return cc_enhanced.check()
    end
    
    -- 回退到原版 CC 逻辑
    if CCDeny then
        local uri = ngx.var.uri
        local CCcount = tonumber(string.match(CCrate, '(.*)/'))
        local CCseconds = tonumber(string.match(CCrate, '/(.*)'))
        local token = getClientIp() .. uri
        local limit = ngx.shared.limit
        local req, _ = limit:get(token)
        if req then
            if req > CCcount then
                if should_block("CCAction") then
                    return ngx.exit(503)
                end
                return true
            else
                limit:incr(token, 1)
            end
        else
            limit:set(token, 1, CCseconds)
        end
    end
    return false
end

-- ============================================================
-- Boundary 获取（multipart）
-- ============================================================

function get_boundary()
    local header = get_headers()["content-type"]
    if not header then
        return nil
    end
    if type(header) == "table" then
        header = header[1]
    end
    local m = match(header, ";%s*boundary=\"([^\"]+)\"")
    if m then
        return m
    end
    return match(header, ";%s*boundary=([^\",;]+)")
end

-- ============================================================
-- IP 白名单（支持 CIDR）
-- ============================================================

function whiteip()
    if next(ipWhitelist) ~= nil then
        local client_ip = getClientIp()
        if utils.ip_in_list(client_ip, ipWhitelist) then
            return true
        end
    end
    return false
end

-- ============================================================
-- IP 黑名单（支持 CIDR）
-- ============================================================

function blockip()
    if next(ipBlocklist) ~= nil then
        local client_ip = getClientIp()
        if utils.ip_in_list(client_ip, ipBlocklist) then
            log('GET', ngx.var.request_uri, "-", "[IPBLOCK][403] hit=[" .. client_ip .. "]")
            if should_block("IPBlockAction") then
                return ngx.exit(403)
            end
            return true
        end
    end
    return false
end

-- ============================================================
-- 危险路径/文件检测（dangerous 规则）
-- ============================================================

function dangerous()
    if BlockDangerousCheck then
        if dgrules ~= nil then
            for _, item in pairs(dgrules) do
                local rule = item.rule
                local tag = item.tag
                if not BlockAggressiveCheck and tag == "aggressive" then
                    -- 激进规则已关闭，跳过
                elseif rule ~= "" then
                    local m = ngx.re.match(ngx.var.request_uri, rule, "isj")
                    if m then
                        local hit = string.sub(m[0] or "-", 1, 200)
                        log('GET', ngx.var.request_uri, "-", "[DANGEROUS][" .. tag .. "][404] hit=[" .. hit .. "] rule=" .. rule)
                        ngx.log(ngx.ERR, "WAF_DEBUG: should_block(DangerousAction)=", tostring(should_block("DangerousAction")))
                        if should_block("DangerousAction") then
                            return say_html(ngx.HTTP_NOT_FOUND)
                        end
                        return true
                    end
                end
            end
        end
    end
    return false
end

-- ============================================================
-- Referer 检查
-- ============================================================

function referer()
    if BlockRefererCheck then
        local referer = ngx.var.http_referer
        if referer ~= nil and refererrules ~= nil then
            for _, rule in pairs(refererrules) do
                if rule ~= "" then
                    local m = cache.match_cached(referer, rule, "isj")
                    if m then
                        local hit = string.sub(m[0] or "-", 1, 200)
                        log('GET', ngx.var.request_uri, "-", "[REFERER][403] hit=[" .. hit .. "] rule=" .. rule)
                        if should_block("RefererAction") then
                            return say_html()
                        end
                        return true
                    end
                end
            end
        end
    end
    return false
end

-- ============================================================
-- HTTP 方法检查
-- ============================================================

function methodcheck()
    if BlockMethodCheck then
        local method = ngx.req.get_method()
        if methodrules ~= nil then
            for _, rule in pairs(methodrules) do
                if rule ~= "" then
                    local m = cache.match_cached(method, rule, "isj")
                    if m then
                        local hit = string.sub(m[0] or "-", 1, 200)
                        log('GET', ngx.var.request_uri, "-", "[METHOD][403] hit=[" .. hit .. "] rule=" .. rule)
                        if should_block("MethodAction") then
                            return ngx.exit(403)
                        end
                        return true
                    end
                end
            end
        end
    end
    return false
end

-- ============================================================
-- 路径穿越检测
-- ============================================================

function traversal()
    local request_uri = ngx.var.request_uri
    if request_uri ~= nil then
        local m = cache.match_cached(request_uri, [[(\.\./|%2e%2e|%252e|\%00)]], "isj")
        if m then
            local hit = string.sub(m[0] or "-", 1, 200)
            log('GET', request_uri, "-", "[TRAVERSAL][400] hit=[" .. hit .. "] path_traversal")
            if should_block("TraversalAction") then
                return ngx.exit(400)
            end
            return true
        end
    end
    return false
end

-- ============================================================
-- Header 攻击检测
-- ============================================================

function headers()
    if BlockHeaderCheck then
        local headers = ngx.req.get_headers()
        for hname, hval in pairs(headers) do
            if type(hval) == "table" then
                hval = table.concat(hval, ", ")
            end
            for _, rule in pairs(headerrules or {}) do
                if rule ~= "" then
                    local target = tostring(hname) .. ": " .. tostring(hval)
                    local m = cache.match_cached(target, rule, "isj")
                    if m then
                        local hit = string.sub(m[0] or "-", 1, 200)
                        log('GET', ngx.var.request_uri, "-", "[HEADER][403] hit=[" .. hit .. "] header=" .. hname .. " rule=" .. rule)
                        if should_block("HeaderAction") then
                            return say_html()
                        end
                        return true
                    end
                end
            end
        end
    end
    return false
end

-- ============================================================
-- 响应过滤
-- ============================================================

function response_filter()
    if BlockResponseCheck then
        local chunk = ngx.arg[1]
        if chunk and chunk ~= "" then
            for _, rule in pairs(responserules or {}) do
                if rule ~= "" then
                    local m = cache.match_cached(chunk, rule, "isj")
                    if m then
                        local hit = string.sub(m[0] or "-", 1, 200)
                        log('GET', ngx.var.request_uri, "-", "[RESPONSE][500] hit=[" .. hit .. "] rule=" .. rule)
                        if should_block("ResponseAction") then
                            ngx.arg[1] = "<html><body><h1>Internal Server Error</h1></body></html>"
                            ngx.arg[2] = true
                        end
                        return
                    end
                end
            end
        end
    end
end

-- ============================================================
-- 管理接口（可选，用于热更新）
-- ============================================================

function _G.waf_reload_rules()
    cache.reload_all()
    -- 重新加载所有规则
    urlrules = read_rule('url')
    argsrules = read_rule('args')
    uarules = read_rule('user-agent')
    wturlrules = read_rule('whiteurl')
    postrules = read_rule('post')
    ckrules = read_rule('cookie')
    dgrules = read_tagged_rule('dangerous')
    refererrules = read_rule('referer')
    methodrules = read_rule('method')
    headerrules = read_rule('header')
    responserules = read_rule('response')
    ngx.log(ngx.NOTICE, "WAF rules reloaded manually")
    return true
end
