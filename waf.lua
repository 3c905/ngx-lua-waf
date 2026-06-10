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
        ngx.status = 413
        ngx.say("Request Entity Too Large")
        ngx.exit(413)
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
    ngx.exit(444)
elseif ngx.var.http_X_Scan_Memo then
    ngx.exit(444)
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
