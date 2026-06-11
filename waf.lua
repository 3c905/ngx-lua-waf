require 'init'

local content_length = tonumber(ngx.req.get_headers()['content-length'])
local method = ngx.req.get_method()
local ngxmatch = ngx.re.match

local MAX_BODY_SIZE = 10 * 1024 * 1024
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

if whiteip() then
    -- pass
elseif blockip() then
    -- blocked
elseif methodcheck() then
elseif traversal() then
elseif whiteurl() then
elseif headers() then
elseif denycc() then
elseif ngx.var.http_Acunetix_Aspect then
    if should_block("ScannerAction") then ngx.exit(444) end
elseif ngx.var.http_X_Scan_Memo then
    if should_block("ScannerAction") then ngx.exit(444) end
elseif referer() then
elseif ua() then
elseif dangerous() then
elseif url() then
elseif args() then
elseif cookie() then
elseif PostCheck then
    if method == "POST" then
        local boundary = get_boundary()
        if boundary then
            local len = string.len
            local sock, err = ngx.req.socket()
            if not sock then
                return
            end
            ngx.req.init_body(128 * 1024)
            sock:settimeout(0)
            local content_length = tonumber(ngx.req.get_headers()['content-length'])
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
                size = size + len(data)
            end
        else
            ngx.req.read_body()
            local args = ngx.req.get_post_args()
            if args then
                for key, val in pairs(args) do
                    if type(val) == 'table' then
                        local t = {}
                        for k, v in pairs(val) do
                            if v == true then
                                v = ""
                            end
                            table.insert(t, v)
                        end
                        data = table.concat(t, " ")
                    else
                        data = val
                    end
                    if data and data ~= "" then
                        local decoded = utils.decode_chain(unescape(data), 3)
                        for _, rule in pairs(postrules or {}) do
                            if rule ~= "" then
                                local m = cache.match_cached(decoded, rule, "isj")
                                if m then
                                    log('POST', ngx.var.request_uri, "-", "[POST][403] hit=[" .. string.sub(m[0] or "-", 1, 200) .. "] rule=" .. rule)
                                    if should_block("PostAction") then
                                        say_html()
                                    end
                                    return
                                end
                            end
                        end
                    end
                end
            end
        end
    end
end
