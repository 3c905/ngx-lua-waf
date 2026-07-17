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
-- 使用全局函数 + 惰性加载，避免 worker fork 后丢失局部变量
local _cc_enhanced = nil

function _G.get_cc_enhanced()
    if _cc_enhanced and _cc_enhanced.config.enabled then
        return _cc_enhanced
    end
    if optionIsOn(CCEnhanced) then
        _cc_enhanced = require "cc_enhanced"
        _cc_enhanced.config.enabled = true
        _cc_enhanced.config.global_rate = CCGlobalRate or "2000/60"
        _cc_enhanced.config.static_enabled = optionIsOn(CCStaticEnabled)
        _cc_enhanced.config.static_rate = CCStaticRate or "600/60"
        _cc_enhanced.config.static_no_referer_rate = CCStaticNoRefererRate or "200/60"
        _cc_enhanced.config.static_no_cookie_rate = CCStaticNoCookieRate or "300/60"
        _cc_enhanced.config.dynamic_rate = CCDynamicRate or "120/60"
        _cc_enhanced.config.api_rate = CCApiRate or "300/60"
        _cc_enhanced.config.upload_rate = CCUploadRate or "30/60"
        _cc_enhanced.config.post_multiplier = CCPostMultiplier or 0.5
        _cc_enhanced.config.progressive = optionIsOn(CCProgressive)
        _cc_enhanced.config.ban_duration_1 = CCBanDuration1 or 60
        _cc_enhanced.config.ban_duration_2 = CCBanDuration2 or 300
        _cc_enhanced.config.ban_duration_3 = CCBanDuration3 or 3600
        _cc_enhanced.config.challenge_enabled = optionIsOn(CCChallengeEnabled)
        _cc_enhanced.config.challenge_cookie = CCChallengeCookie or "_waf_cc"
        _cc_enhanced.config.challenge_ttl = CCChallengeTTL or 300
    end
    return _cc_enhanced
end

-- 初始加载（master 阶段）
get_cc_enhanced()

-- ============================================================
-- 防御性处理：确保关键配置变量生效
-- ============================================================
if attacklog == nil then
    ngx.log(ngx.ERR, "WAF_CONFIG_ERROR: attacklog is nil after require 'config'. ",
            "config.lua may not be loaded correctly or variable name mismatch. ",
            "_G.attacklog=", tostring(_G.attacklog or "nil"), " ",
            "logdir=", tostring(logdir or "nil"), " ",
            "rulepath=", tostring(RulePath or "nil"))
    -- 强制兜底，确保日志功能可用
    attacklog = "on"
end

-- ============================================================
-- 全局配置变量（保持向后兼容）
-- ============================================================
logpath = logdir and string.gsub(logdir, "\r$", "") or "/tmp"
if logpath ~= "/" and string.sub(logpath, -1) == "/" then
    logpath = string.sub(logpath, 1, -2)
end
rulepath = RulePath and string.gsub(RulePath, "\r$", "") or "/tmp/"
if rulepath ~= "/" and string.sub(rulepath, -1) ~= "/" then
    rulepath = rulepath .. "/"
end
UrlDeny = optionIsOn(UrlDeny)
PostCheck = optionIsOn(postMatch)
CookieCheck = optionIsOn(CookieMatch)
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

-- WAF 调试日志开关
wafDebug = optionIsOn(WafDebug)

function waf_debug(...)
    if wafDebug then
        ngx.log(ngx.ERR, ...)
    end
end

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
        waf_debug("WAF_WRITE_FAIL: file=", logfile, " err=", tostring(err), " ip=", getClientIp(), " uri=", ngx.var.request_uri)
        return false, err
    end
    fd:write(msg)
    fd:flush()
    fd:close()
    return true
end

function log(method, url, data, ruletag)
    if not attacklog then
        waf_debug("WAF_LOG_SKIP: attacklog=off ip=", getClientIp(), " uri=", ngx.var.request_uri, " rule=", ruletag)
        return
    end
    
    local realIp = getClientIp()
    local ua = ngx.var.http_user_agent
    local servername = ngx.var.server_name or "_"
    local time = ngx.localtime()
    local filename = logpath .. "/" .. servername .. "_" .. ngx.today() .. "_sec.log"
    
    -- 日志限流检查
    if LogRateLimit and LogRateLimit > 0 then
        local limit_key = realIp .. ":" .. ruletag
        local now = math.floor(ngx.now())
        local window = math.floor(now / 60)  -- 60 秒窗口
        local window_key = limit_key .. ":" .. window
        
        local current = log_limiter[window_key] or 0
        if current >= LogRateLimit then
            waf_debug("WAF_LOG_RATELIMIT: key=", window_key, " limit=", LogRateLimit)
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
    
    local ok, err = write(filename, line)
    if ok then
        waf_debug("WAF_LOG_OK: file=", filename, " line=", string.gsub(line, "\n", ""))
    else
        waf_debug("WAF_LOG_FAIL: file=", filename, " err=", tostring(err), " line=", string.gsub(line, "\n", ""))
    end
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
headerrules = read_tagged_rule('header')
responserules = read_rule('response')

-- 规则加载汇总日志（方便排查规则文件是否加载成功）
local function rule_count(rules)
    if not rules then return "nil" end
    local c = 0
    for _ in pairs(rules) do c = c + 1 end
    return tostring(c)
end

waf_debug("WAF_RULES_LOADED: url=" .. rule_count(urlrules),
        " args=" .. rule_count(argsrules),
        " ua=" .. rule_count(uarules),
        " whiteurl=" .. rule_count(wturlrules),
        " post=" .. rule_count(postrules),
        " cookie=" .. rule_count(ckrules),
        " dangerous=" .. rule_count(dgrules),
        " referer=" .. rule_count(refererrules),
        " method=" .. rule_count(methodrules),
        " header=" .. rule_count(headerrules),
        " response=" .. rule_count(responserules),
        " rulepath=" .. tostring(rulepath or "nil"))

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

-- 预计算文件扩展名黑名单集合（避免每次请求重复构建）
local file_ext_blacklist_set = nil
local function get_file_ext_blacklist_set()
    if not file_ext_blacklist_set then
        file_ext_blacklist_set = {}
        for _, l in ipairs(black_fileExt or {}) do
            file_ext_blacklist_set[string.lower(l)] = true
        end
    end
    return file_ext_blacklist_set
end

function fileExtCheck(ext)
    if not ext or ext == "" then
        return false
    end
    ext = string.lower(ext)
    local items = get_file_ext_blacklist_set()
    if items[ext] then
        log('POST', ngx.var.request_uri, "-", "[FILEEXT][403] hit=[" .. ext .. "]")
        if should_block("FileExtAction") then
            return say_html()
        end
        return true
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
    local args = ngx.req.get_uri_args()
    for _, rule in pairs(argsrules or {}) do
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
    local cc_enhanced_inst = get_cc_enhanced()
    if cc_enhanced_inst then
        return cc_enhanced_inst.check()
    end
    
    -- 回退到原版 CC 逻辑
    if CCDeny then
        local uri = ngx.var.uri or "/"
        local CCcount = tonumber(string.match(CCrate or "", '(.*)/'))
        local CCseconds = tonumber(string.match(CCrate or "", '/(.*)'))
        if not CCcount or not CCseconds then
            waf_debug("WAF_CC_CONFIG_ERROR: invalid CCrate=", tostring(CCrate))
            return false
        end
        local token = getClientIp() .. uri
        local limit = ngx.shared.limit
        if not limit then
            waf_debug("WAF_CC_LIMIT_DICT_MISSING: shared dict 'limit' not configured")
            return false
        end
        local req, _ = limit:get(token)
        if req then
            if req > CCcount then
                log('GET', ngx.var.request_uri, "-", "[CC][503] hit=[count=" .. tostring(req) .. "/limit=" .. tostring(CCcount) .. "] token=" .. token)
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
                    local m = cache.match_cached(ngx.var.request_uri, rule, "isj")
                    if m then
                        local hit = string.sub(m[0] or "-", 1, 200)
                        log('GET', ngx.var.request_uri, "-", "[DANGEROUS][" .. tag .. "][404] hit=[" .. hit .. "] rule=" .. rule)
                        waf_debug("WAF_DEBUG: should_block(DangerousAction)=", tostring(should_block("DangerousAction")))
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
        local m = cache.match_cached(request_uri, [[(\.\./|\.(%2e)|(%2e)\.|%2e%2e|%252e|%%32%65|\%00)]], "isj")
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
        -- 请求走私：Content-Length 与 Transfer-Encoding 同时出现（RFC 7230 禁止，浏览器/curl 不会发送）
        if headers["content-length"] and headers["transfer-encoding"] then
            log('GET', ngx.var.request_uri, "-", "[HEADER][403] hit=[CL+TE] request_smuggling")
            if should_block("HeaderAction") then
                return say_html()
            end
            return true
        end
        for hname, hval in pairs(headers) do
            if type(hval) == "table" then
                hval = table.concat(hval, ", ")
            end
            for _, item in pairs(headerrules or {}) do
                local rule = item.rule
                local tag = item.tag
                if not BlockAggressiveCheck and tag == "aggressive" then
                    -- 激进规则已关闭，跳过
                elseif rule ~= "" then
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
                            ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
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
    headerrules = read_tagged_rule('header')
    responserules = read_rule('response')
    -- 刷新文件扩展名黑名单集合（config 可能已更新）
    file_ext_blacklist_set = nil
    ngx.log(ngx.NOTICE, "WAF rules reloaded manually")
    return true
end
