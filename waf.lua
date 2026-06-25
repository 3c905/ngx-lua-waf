require 'init'
local cache = require "cache"
local utils = require "utils"

-- ============================================================
-- waf-cli 命令处理（文件管道）
-- 通过 WafCmdDir/req-*.json 接收命令，写入 res-*.json 返回结果
-- 每 0.1 秒最多检查一次，避免频繁 IO；需要至少一个 HTTP 请求触发
-- ============================================================
local function json_escape(s)
    if s == nil then return "null" end
    s = tostring(s)
    s = string.gsub(s, '\\', '\\\\')
    s = string.gsub(s, '"', '\\"')
    s = string.gsub(s, '\n', '\\n')
    s = string.gsub(s, '\r', '\\r')
    s = string.gsub(s, '\t', '\\t')
    return '"' .. s .. '"'
end

local function write_res(file, status, message, data)
    local res = string.format('{"status":%s,"message":%s,"data":%s}\n',
        json_escape(status), json_escape(message), data or "null")
    local fd, err = io.open(file, "w")
    if fd then
        fd:write(res)
        fd:close()
    else
        waf_debug("WAF_CMD_WRITE_FAIL: file=", file, " err=", tostring(err))
    end
end

local function banlist_to_json(list)
    if not list or #list == 0 then return "[]" end
    local parts = {}
    for _, item in ipairs(list) do
        table.insert(parts, string.format('{"ip":%s,"level":%s,"ttl":%s,"remain":%s}',
            json_escape(item.ip),
            tostring(item.level or 0),
            tostring(item.ttl or 0),
            tostring(item.remain or 0)))
    end
    return "[" .. table.concat(parts, ",") .. "]"
end

local function stats_to_json(stats)
    if not stats then return "null" end
    return string.format('{"ip":%s,"global":%s,"static":%s,"static_noref":%s,"dynamic":%s,"api":%s,"upload":%s,"history":%s,"banned":%s,"ban_level":%s,"ban_ttl":%s}',
        json_escape(stats.ip),
        tostring(stats.global or 0),
        tostring(stats.static or 0),
        tostring(stats.static_noref or 0),
        tostring(stats.dynamic or 0),
        tostring(stats.api or 0),
        tostring(stats.upload or 0),
        tostring(stats.history or 0),
        stats.banned and "true" or "false",
        tostring(stats.ban_level or 0),
        tostring(stats.ban_ttl or 0))
end

local function process_waf_commands()
    waf_debug("WAF_CMD_CHECK_START")
    local cc_dict = ngx.shared.waf_cc
    if not cc_dict then
        waf_debug("WAF_CMD_NO_CC_DICT")
        return
    end

    -- 每 0.1 秒最多检查一次，既限制 IO 又保证 waf-cli 响应及时
    local now = ngx.now()
    local last_check = cc_dict:get("_waf_cmd_last_check")
    if last_check and (now - last_check) < 0.1 then
        return
    end
    cc_dict:set("_waf_cmd_last_check", now, 1)

    local cmd_dir = WafCmdDir or "/tmp/waf-cmd"
    waf_debug("WAF_CMD_DIR: dir=", cmd_dir)

    -- 每分钟检查并确保命令目录存在（/var/run 等 tmpfs 重启后会丢失）
    local dir_check_key = "_waf_cmd_dir_check"
    if not cc_dict:get(dir_check_key) then
        local ok = os.execute("mkdir -p " .. cmd_dir)
        if not ok then
            waf_debug("WAF_CMD_DIR_FAIL: dir=", cmd_dir)
            return
        end
        cc_dict:set(dir_check_key, 1, 60)
    end

    -- 检查目录是否可读写
    local test_file = cmd_dir .. "/.waf_write_test"
    local test_fd = io.open(test_file, "w")
    if test_fd then
        test_fd:close()
        os.remove(test_file)
    else
        ngx.log(ngx.ERR, "WAF_CMD_DIR_NOT_WRITABLE: dir=", cmd_dir,
            " user=", tostring(ngx.var.remote_user or "-"),
            " please chown ", cmd_dir, " to nginx worker user")
        return
    end

    -- 列出待处理命令文件
    local list_cmd = "ls -1 " .. cmd_dir .. "/req-*.json 2>/dev/null"
    local pipe, err = io.popen(list_cmd)
    if not pipe then
        waf_debug("WAF_CMD_LS_FAIL: err=", tostring(err), " cmd=", list_cmd)
        return
    end

    local file_count = 0
    for file in pipe:lines() do
        file_count = file_count + 1
        waf_debug("WAF_CMD_FOUND: file=", file)
        local fd = io.open(file, "r")
        if fd then
            local content = fd:read("*all")
            fd:close()

            local cmd = string.match(content, '"cmd"%s*:%s*"([^"]+)"')
            local ip = string.match(content, '"ip"%s*:%s*"([^"]+)"')
            local res_file = string.gsub(file, "req%-", "res%-")

            local status, message, data = "error", "unknown cmd", "null"
            local cc_inst = get_cc_enhanced and get_cc_enhanced()

            if cmd == "banlist" then
                if cc_inst then
                    local list, err = cc_inst.get_ban_list()
                    if list then
                        status, message, data = "ok", nil, banlist_to_json(list)
                    else
                        status, message = "error", err or "failed"
                    end
                else
                    status, message = "error", "CCEnhanced is off, CC block IP feature is disabled. Set CCEnhanced = \"on\" and restart nginx to enable banlist/unban/stats."
                end
            elseif cmd == "unban" then
                if not ip or ip == "" then
                    status, message = "error", "ip required"
                elseif cc_inst then
                    local ok, err = cc_inst.unban_ip(ip)
                    if ok then
                        status, message = "ok", "unbanned " .. ip
                    else
                        status, message = "error", err or "failed"
                    end
                else
                    status, message = "error", "CCEnhanced is off, CC block IP feature is disabled. Set CCEnhanced = \"on\" and restart nginx to enable banlist/unban/stats."
                end
            elseif cmd == "stats" then
                if cc_inst then
                    local stats = cc_inst.get_stats(ip)
                    if stats then
                        status, message, data = "ok", nil, stats_to_json(stats)
                    else
                        status, message = "error", "failed to get stats"
                    end
                else
                    status, message = "error", "CCEnhanced is off, CC block IP feature is disabled. Set CCEnhanced = \"on\" and restart nginx to enable banlist/unban/stats."
                end
            elseif cmd == "reload" then
                if _G.waf_reload_rules then
                    _G.waf_reload_rules()
                    status, message = "ok", "rules reloaded"
                else
                    status, message = "error", "reload function not available"
                end
            end

            write_res(res_file, status, message, data)
            os.remove(file)
            waf_debug("WAF_CMD: cmd=", cmd, " ip=", tostring(ip), " status=", status)
        end
    end
    pipe:close()
    waf_debug("WAF_CMD_LS_DONE: count=", file_count)
end

process_waf_commands()

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
