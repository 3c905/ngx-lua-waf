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

-- 防御性兜底：init.lua 若被二次执行（require 'init' 重入），同名布尔
-- 开关会被 optionIsOn 翻转为 false；init.lua 末尾已通过
-- package.loaded["init"]=true 根治，此处仅作最后防线
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
    if method == "POST" or method == "PUT" or method == "PATCH" then
        -- 辅助：从已读 body 中扫描文件扩展名 + 文件内容（图片马/脚本马）
        -- 内容特征均为 >=5 字节，避免命中图片二进制中的随机字节序列
        local upload_image_ext = {
            jpg = true, jpeg = true, png = true, gif = true, bmp = true,
            webp = true, ico = true, svg = true,
        }
        local upload_content_sigs = {
            "<?php", "<script", "<jsp:", "<%@page", "<%eval", "<%exec", "#!/bin/",
        }
        local function scan_multipart_body(body)
            if not body or body == "" then return false end
            local pos = 1
            while true do
                local s, e, fname = string.find(body, 'filename="([^"]+)"', pos)
                if not s then break end
                local ext = string.match(fname, "%.([a-zA-Z0-9]+)$")
                if ext then
                    local lext = string.lower(ext)
                    -- 1. 扩展名黑名单
                    if fileExtCheck(lext) then
                        waf_debug("WAF_POST_FILEEXT_BLOCK: ip=", client_ip, " uri=", request_uri, " file=", fname)
                        return true
                    end
                    -- 2. 图片类扩展名：嗅探 part 内容前 64KB 是否夹带脚本
                    if upload_image_ext[lext] then
                        local hs, he = string.find(body, "\r\n\r\n", e, true)
                        if hs then
                            local bs = string.find(body, "\r\n--", he + 1, true)
                            local cend = bs and (bs - 1) or (he + 65536)
                            local content = string.sub(body, he + 1, math.min(cend, he + 65536))
                            if content and content ~= "" then
                                local lowered = string.lower(content)
                                for _, sig in ipairs(upload_content_sigs) do
                                    if string.find(lowered, sig, 1, true) then
                                        log('POST', ngx.var.request_uri, "-", "[UPLOAD-CONTENT][403] hit=[" .. sig .. "] file=" .. fname)
                                        waf_debug("WAF_POST_CONTENT_BLOCK: ip=", client_ip, " uri=", request_uri, " file=", fname, " sig=", sig)
                                        if should_block("FileExtAction") then
                                            return say_html()
                                        end
                                        return true
                                    end
                                end
                            end
                        end
                    end
                end
                pos = e + 1
            end
            return false
        end

        -- 辅助：兜底读取 body（内存或临时文件）用于扫描
        local function get_body_for_scan()
            ngx.req.read_body()
            local body = ngx.req.get_body_data()
            if body then return body end
            local file_path = ngx.req.get_body_file()
            if file_path then
                local fd, open_err = io.open(file_path, "rb")
                if fd then
                    local data, read_err = fd:read(MAX_BODY_SIZE)
                    fd:close()
                    if data then return data end
                    waf_debug("WAF_POST_FILE_READ_FAIL: ip=", client_ip, " err=", tostring(read_err))
                else
                    waf_debug("WAF_POST_FILE_OPEN_FAIL: ip=", client_ip, " err=", tostring(open_err))
                end
            end
            return nil
        end

        local boundary = get_boundary()

        if boundary then
            -- ============================================================
            -- multipart 文件上传：流式读取 + 重建 body
            -- ============================================================
            -- 关键：ngx.req.socket() 读取后必须自己 append_body() 重建，
            -- 否则后端/proxy_pass 会收到空 body。
            local content_length = tonumber(ngx.req.get_headers()['content-length'])
            if not content_length then
                waf_debug("WAF_POST_MULTIPART_NO_LENGTH: ip=", client_ip, " uri=", request_uri)
                -- 没有 Content-Length（通常是 chunked）直接降级到 read_body，
                -- 避免 socket receive 因未知大小而阻塞
                local body = get_body_for_scan()
                if scan_multipart_body(body) then return end
                waf_debug("WAF_POST_MULTIPART_PASS: ip=", client_ip, " uri=", request_uri, " mode=chunked_fallback")
            elseif content_length > MAX_BODY_SIZE then
                waf_debug("WAF_POST_MULTIPART_TOO_LARGE: ip=", client_ip, " uri=", request_uri, " size=", content_length)
                log(method, request_uri, "-", "[BODYLIMIT][413] size=" .. tostring(content_length) .. " max=" .. tostring(MAX_BODY_SIZE))
                if should_block and should_block("BodyLimitAction") then
                    ngx.status = 413
                    ngx.say("Request Entity Too Large")
                    return ngx.exit(413)
                end
            else
                local sock, err = ngx.req.socket()
                if not sock then
                    waf_debug("WAF_POST_SOCK_FAIL: ip=", client_ip, " err=", tostring(err))
                    -- socket 不可用，降级到 read_body 兜底
                    local body = get_body_for_scan()
                    if scan_multipart_body(body) then return end
                else
                    -- 初始化 body 缓冲区，准备重建请求体
                    local init_ok, init_err = pcall(ngx.req.init_body, math.min(content_length, 128 * 1024))
                    if not init_ok then
                        waf_debug("WAF_POST_INIT_BODY_FAIL: ip=", client_ip, " err=", tostring(init_err))
                        local body = get_body_for_scan()
                        if scan_multipart_body(body) then return end
                    else
                        sock:settimeout(5000)  -- 5 秒读超时，避免空转
                        local chunk_size = 4096
                        if content_length < chunk_size then
                            chunk_size = content_length
                        end
                        local size = 0
                        local body_buffer = {}

                        while size < content_length do
                            local remain = content_length - size
                            if remain < chunk_size then
                                chunk_size = remain
                            end
                            local data, read_err, partial = sock:receive(chunk_size)
                            data = data or partial
                            if not data or data == "" then
                                waf_debug("WAF_POST_READ_FAIL: ip=", client_ip, " err=", tostring(read_err), " size=", size)
                                break
                            end
                            size = size + string.len(data)
                            -- 重建请求体，确保后端能收到
                            local append_ok, append_err = pcall(ngx.req.append_body, data)
                            if not append_ok then
                                waf_debug("WAF_POST_APPEND_FAIL: ip=", client_ip, " err=", tostring(append_err))
                                break
                            end
                            -- 同时缓存到本地 buffer 做扩展名扫描
                            table.insert(body_buffer, data)
                        end

                        local finish_ok, finish_err = pcall(ngx.req.finish_body)
                        if not finish_ok then
                            waf_debug("WAF_POST_FINISH_BODY_FAIL: ip=", client_ip, " err=", tostring(finish_err))
                        end

                        waf_debug("WAF_POST_MULTIPART_READ: ip=", client_ip, " uri=", request_uri, " size=", size)

                        -- 文件扩展名黑名单检查
                        local body = table.concat(body_buffer)
                        if scan_multipart_body(body) then return end
                    end
                end
                waf_debug("WAF_POST_MULTIPART_PASS: ip=", client_ip, " uri=", request_uri)
            end
        else
            -- ============================================================
            -- 非 multipart：安全地使用 read_body
            -- ============================================================
            ngx.req.read_body()
            -- 参数个数上限：超出即视为异常（防止 padding 绕过和解析型 DoS）
            local MAX_POST_ARGS = 1024
            local args = ngx.req.get_post_args(MAX_POST_ARGS + 1)

            -- 通用 POST 参数扫描
            if args then
                local arg_count = 0
                for key, val in pairs(args) do
                    arg_count = arg_count + 1
                    if arg_count > MAX_POST_ARGS then
                        log('POST', ngx.var.request_uri, "-", "[POST][400] hit=[too many args] count>" .. MAX_POST_ARGS)
                        if should_block("PostAction") then
                            return ngx.exit(400)
                        end
                        return
                    end
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
                    -- 先扫参数值，再扫参数名（防御 user[$ne]=x 类 NoSQL 数组参数注入）
                    for _, target in ipairs({data, key}) do
                        if target and target ~= "" and type(target) ~= "boolean" then
                            local decoded = utils.decode_chain(unescape(target), 3)
                            for _, rule in pairs(postrules or {}) do
                                if rule ~= "" then
                                    local m = cache.match_cached(decoded, rule, "isj")
                                    if not m then
                                        m = cache.match_cached(unescape(target), rule, "isj")
                                    end
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
                end
            end

            -- JSON Body 扫描：针对 CVE-2026-0768 / CVE-2026-21858 / CVE-2025-71333 等 JSON payload
            local content_type_header = ngx.req.get_headers()["content-type"]
            if type(content_type_header) == "table" then
                content_type_header = content_type_header[1]
            end
            local ct = content_type_header or ""
            -- 同时覆盖 application/hal+json、application/vnd.api+json 等 +json 类型
            if string.find(ct, "application/json", 1, true) or string.find(ct, "+json", 1, true) then
                local raw_body = ngx.req.get_body_data()
                if raw_body and raw_body ~= "" then
                    -- 多重解码，覆盖 \u0027 等 Unicode/双重编码绕过
                    local decoded_body = utils.decode_chain(raw_body, 3)
                    for _, rule in pairs(postrules or {}) do
                        if rule ~= "" then
                            local m = cache.match_cached(decoded_body, rule, "isj")
                            if not m then
                                m = cache.match_cached(raw_body, rule, "isj")
                            end
                            if m then
                                log('POST', ngx.var.request_uri, "-", "[POST][403] hit=[" .. string.sub(m[0] or "-", 1, 200) .. "] rule=" .. rule)
                                if should_block("PostAction") then
                                    return say_html()
                                end
                                return
                            end
                        end
                    end
                    waf_debug("WAF_POST_JSON_PASS: ip=", client_ip, " uri=", request_uri)
                end
            end

            if args then
                waf_debug("WAF_POST_BODY_PASS: ip=", client_ip, " uri=", request_uri)
            else
                waf_debug("WAF_POST_NOARGS: ip=", client_ip, " uri=", request_uri)
            end
        end
    end
end

waf_debug("WAF_ALL_PASS: ip=", client_ip, " uri=", request_uri)
