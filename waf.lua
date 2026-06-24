require 'init'
local cache = require "cache"
local utils = require "utils"

-- 防御性兜底：init_by_lua 阶段可能未正确加载 attacklog
if attacklog == nil or attacklog == false then
    attacklog = true
    waf_debug("WAF_FALLBACK: attacklog was nil/false in access phase, forced to true. ",
            "init.lua may need nginx restart to take effect.")
end

local content_length = tonumber(ngx.req.get_headers()['content-length'])
local method = ngx.req.get_method()
local ngxmatch = ngx.re.match
local unescape = ngx.unescape_uri
local client_ip = getClientIp and getClientIp() or (ngx.var.remote_addr or "unknown")
local request_uri = ngx.var.request_uri or "/"
local user_agent = ngx.var.http_user_agent or "-"

-- ============================================================
-- 请求入口跟踪日志
-- ============================================================
waf_debug("WAF_ENTRY: ip=", client_ip,
        " method=", method,
        " uri=", request_uri,
        " ua=", user_agent,
        " clen=", tostring(content_length or "-"),
        " attacklog=", tostring(attacklog or "nil"),
        " logpath=", tostring(logpath or "nil"))

local MAX_BODY_SIZE = 10 * 1024 * 1024
if content_length and content_length > MAX_BODY_SIZE then
    if method == "POST" or method == "PUT" or method == "PATCH" then
        waf_debug("WAF_BODYLIMIT: ip=", client_ip, " uri=", request_uri, " size=", content_length)
        log(method, request_uri, "-", "[BODYLIMIT][413] size=" .. tostring(content_length) .. " max=" .. tostring(MAX_BODY_SIZE))
        if should_block and should_block("BodyLimitAction") then
            ngx.status = 413
            ngx.say("Request Entity Too Large")
            return ngx.exit(413)
        end
    end
end

local function check(name, result)
    if result then
        waf_debug("WAF_BLOCK: module=", name, " ip=", client_ip, " uri=", request_uri)
        return true
    else
        waf_debug("WAF_PASS: module=", name, " ip=", client_ip, " uri=", request_uri)
        return false
    end
end

if whiteip() then
    waf_debug("WAF_WHITEIP: ip=", client_ip, " uri=", request_uri)
    return
elseif check("blockip", blockip()) then
    return
elseif check("methodcheck", methodcheck()) then
    return
elseif check("traversal", traversal()) then
    return
elseif whiteurl() then
    waf_debug("WAF_WHITEURL: ip=", client_ip, " uri=", request_uri)
    return
elseif check("headers", headers()) then
    return
elseif check("denycc", denycc()) then
    return
elseif ngx.var.http_Acunetix_Aspect then
    log('GET', ngx.var.request_uri, "-", "[SCANNER][444] hit=[Acunetix-Aspect]")
    if should_block("ScannerAction") then return ngx.exit(444) end
    return
elseif ngx.var.http_X_Scan_Memo then
    log('GET', ngx.var.request_uri, "-", "[SCANNER][444] hit=[X-Scan-Memo]")
    if should_block("ScannerAction") then return ngx.exit(444) end
    return
elseif check("referer", referer()) then
    return
elseif check("ua", ua()) then
    return
elseif check("dangerous", dangerous()) then
    return
elseif check("url", url()) then
    return
elseif check("args", args()) then
    return
elseif check("cookie", cookie()) then
    return
elseif PostCheck then
    if method == "POST" then
        local boundary = get_boundary()
        if boundary then
            local len = string.len
            local sock, err = ngx.req.socket()
            if not sock then
                waf_debug("WAF_POST_SOCK_FAIL: ip=", client_ip, " err=", tostring(err))
                return
            end
            ngx.req.init_body(128 * 1024)
            sock:settimeout(0)
            local content_length = tonumber(ngx.req.get_headers()['content-length'])
            if not content_length then
                waf_debug("WAF_POST_MULTIPART_NO_LENGTH: ip=", client_ip, " uri=", request_uri)
                return
            end
            local chunk_size = 4096
            if content_length < chunk_size then
                chunk_size = content_length
            end
            local size = 0
            while size < content_length do
                local data, err, partial = sock:receive(chunk_size)
                data = data or partial
                if not data then
                    waf_debug("WAF_POST_READ_FAIL: ip=", client_ip, " err=", tostring(err))
                    return
                end
                size = size + len(data)
            end
            waf_debug("WAF_POST_MULTIPART_PASS: ip=", client_ip, " uri=", request_uri, " size=", size)
        else
            ngx.req.read_body()
            local args = ngx.req.get_post_args()
            if args then
                for key, val in pairs(args) do
                    local data
                    if type(val) == 'table' then
                        local t = {}
                        for k, v in pairs(val) do
                            if v == true then
                                v = ""
                            end
                            table.insert(t, v)
                        end
                        data = table.concat(t, " ")
                    elseif val == true then
                        data = ""
                    else
                        data = val
                    end
                    if data and data ~= "" and type(data) ~= "boolean" then
                        local decoded = utils.decode_chain(unescape(data), 3)
                        for _, rule in pairs(postrules or {}) do
                            if rule ~= "" then
                                local m = cache.match_cached(decoded, rule, "isj")
                                if m then
                                    log('POST', ngx.var.request_uri, "-", "[POST][403] hit=[" .. string.sub(m[0] or "-", 1, 200) .. "] rule=" .. rule)
                                    if should_block("PostAction") then
                                        return say_html()
                                    end
                                    return
                                end
                            end
                        end
                    end
                end
                waf_debug("WAF_POST_BODY_PASS: ip=", client_ip, " uri=", request_uri)
            else
                waf_debug("WAF_POST_NOARGS: ip=", client_ip, " uri=", request_uri)
            end
        end
    end
end

waf_debug("WAF_ALL_PASS: ip=", client_ip, " uri=", request_uri)
