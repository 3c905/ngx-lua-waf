local content_length = tonumber(ngx.req.get_headers()['content-length'])
local method = ngx.req.get_method()
local ngxmatch = ngx.re.match

-- ============================================================
-- 请求体大小限制（防 DoS）
-- ============================================================
local MAX_BODY_SIZE = 10 * 1024 * 1024  -- 10MB，可调整
if content_length and content_length > MAX_BODY_SIZE then
    if method == "POST" or method == "PUT" or method == "PATCH" then
        ngx.log(ngx.WARN, "WAF: request body too large: ", content_length)
        if should_block and should_block("BodyLimitAction") then
            ngx.status = 413
            ngx.say("Request Entity Too Large")
            ngx.exit(413)
        end
    end
end

-- ============================================================
-- WAF 检测链（优化顺序）
-- ============================================================
-- 顺序原则：
-- 1. 白名单优先放行（减少后续检测开销）
-- 2. 无状态检测优先（IP黑白、路径穿越）
-- 3. 有状态检测后置（CC、Referer依赖上下文）
-- 4. 高开销检测最后（POST体解析）

if whiteip() then
    -- IP 白名单直接放行
elseif blockip() then
    -- IP 黑名单阻断
elseif methodcheck() then
    -- HTTP 方法检查
elseif traversal() then
    -- 路径穿越/空字节
elseif whiteurl() then
    -- URL 白名单放行（静态资源等不应被 CC 拦截）
elseif headers() then
    -- Header 层攻击检测
elseif denycc() then
    -- CC 防护（在白名单之后，避免误杀正常白名单流量）
elseif ngx.var.http_Acunetix_Aspect then
    ngx.log(ngx.WARN, "WAF: Scanner detected: Acunetix_Aspect")
    if should_block and should_block("ScannerAction") then
        ngx.exit(444)
    end
elseif ngx.var.http_X_Scan_Memo then
    ngx.log(ngx.WARN, "WAF: Scanner detected: X-Scan-Memo")
    if should_block and should_block("ScannerAction") then
        ngx.exit(444)
    end
elseif referer() then
    -- 恶意 Referer
elseif ua() then
    -- User-Agent 黑名单
elseif dangerous() then
    -- 敏感路径/文件
elseif url() then
    -- URL 黑名单
elseif args() then
    -- GET 参数攻击检测
elseif cookie() then
    -- Cookie 攻击检测
elseif PostCheck then
    -- POST 请求体检测
    if method == "POST" then
        local boundary = get_boundary()
        if boundary then
            -- multipart 上传
            local len = string.len
            local sock, err = ngx.req.socket()
            if not sock then
                return
            end
            ngx.req.init_body(128 * 1024)
            sock:settimeout(0)
            local content_length = nil
            content_length = tonumber(ngx.req.get_headers()['content-length'])
            local chunk_size = 4096
            if content_length < chunk_size then
                chunk_size = content_length
            end
            local size = 0
            while size < content_length do
                local data, err, partial = sock:receive(chunk_size)
                data = data or partial
                if not data then
                    return
                end
                ngx.req.append_body(data)
                if body(data) then
                    return true
                end
                size = size + len(data)
                local m = ngxmatch(data, [[Content-Disposition: form-data;(.+)filename="(.+)\.(.*)"]], 'ijo')
                if m then
                    fileExtCheck(m[3])
                    filetranslate = true
                else
                    if ngxmatch(data, "Content-Disposition:", 'isjo') then
                        filetranslate = false
                    end
                    if filetranslate == false then
                        if body(data) then
                            return true
                        end
                    end
                end
                local less = content_length - size
                if less < chunk_size then
                    chunk_size = less
                end
            end
            ngx.req.finish_body()
        else
            -- 普通表单 POST
            ngx.req.read_body()
            local args = ngx.req.get_post_args()
            if not args then
                return
            end
            for key, val in pairs(args) do
                if type(val) == "table" then
                    if type(val[1]) == "boolean" then
                        return
                    end
                    data = table.concat(val, ", ")
                else
                    data = val
                end
                if data and type(data) ~= "boolean" and body(data) then
                    body(key)
                end
            end
        end
    end
else
    return
end

-- ============================================================
-- 命令行管理工具：文件管道处理
-- ============================================================
-- 命令行工具 waf-cli 通过 /tmp/waf-cmd/ 目录下的文件与 WAF 通信
-- 无需开放 HTTP 接口，适合安全管控严格的生产环境

local function simple_json_encode(obj)
    local t = type(obj)
    if t == "string" then
        return string.format("%q", obj)
    elseif t == "number" or t == "boolean" then
        return tostring(obj)
    elseif t == "table" then
        local parts = {}
        if #obj > 0 then
            for _, v in ipairs(obj) do
                table.insert(parts, simple_json_encode(v))
            end
            return "[" .. table.concat(parts, ",") .. "]"
        else
            for k, v in pairs(obj) do
                table.insert(parts, string.format("%q:%s", k, simple_json_encode(v)))
            end
            return "{" .. table.concat(parts, ",") .. "}"
        end
    end
    return "null"
end

local function process_waf_cli_commands()
    local cmd_dir = WafCmdDir
    if not cmd_dir then return end

    -- 频率限制：每 1 秒最多检查一次，避免每次请求都执行 ls
    local dict = ngx.shared.limit
    if dict then
        local last = dict:get("waf_cmd_last_check") or 0
        local now = ngx.now()
        if now - last < 1 then
            return
        end
        dict:set("waf_cmd_last_check", now)
    end

    -- 读取请求文件列表
    local fd = io.popen("ls " .. cmd_dir .. "/req-*.json 2>/dev/null")
    if not fd then return end

    for req_file in fd:lines() do
        local req_fd = io.open(req_file, "r")
        if req_fd then
            local content = req_fd:read("*a")
            req_fd:close()

            -- 解析简单 JSON
            local cmd = string.match(content, '"cmd"%s*:%s*"([^"]+)"')
            local id = string.match(content, '"id"%s*:%s*"([^"]+)"') or "unknown"
            local ip = string.match(content, '"ip"%s*:%s*"([^"]+)"')

            local res = {status = "ok"}

            if cmd == "unban" and ip then
                local cc = require "cc_enhanced"
                local ok, err = cc.unban_ip(ip)
                if not ok then
                    res.status = "error"
                    res.message = err or "unban failed"
                else
                    res.message = "ip unbanned"
                    res.ip = ip
                end

            elseif cmd == "banlist" then
                local cc = require "cc_enhanced"
                local list, err = cc.get_ban_list()
                if list then
                    res.count = #list
                    res.data = list
                else
                    res.status = "error"
                    res.message = err or "failed to get banlist"
                end

            elseif cmd == "reload" then
                local ok = waf_reload_rules()
                if ok then
                    res.message = "rules reloaded"
                else
                    res.status = "error"
                    res.message = "reload failed"
                end

            elseif cmd == "stats" and ip then
                local cc = require "cc_enhanced"
                local stats = cc.get_stats(ip)
                if stats then
                    res.data = stats
                else
                    res.status = "error"
                    res.message = "no stats available"
                end

            else
                res.status = "error"
                res.message = "unknown command or missing parameters"
            end

            -- 写入响应文件
            local res_file = cmd_dir .. "/res-" .. id .. ".json"
            local res_fd = io.open(res_file, "w")
            if res_fd then
                res_fd:write(simple_json_encode(res))
                res_fd:close()
            end

            -- 删除请求文件
            os.remove(req_file)
        end
    end

    fd:close()
end

process_waf_cli_commands()
