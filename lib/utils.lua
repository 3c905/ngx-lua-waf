local _M = {}

-- ============================================================
-- 1. 真实 IP 获取（X-Forwarded-For 解析）
-- ============================================================

-- 配置：信任的前置代理 IP 段（CIDR 格式）
local trusted_proxies = _M.trusted_proxies or {}

-- 解析 X-Forwarded-For，返回最左侧非信任代理的真实 IP
function _M.get_real_ip()
    local remote_addr = ngx.var.remote_addr or "unknown"
    
    -- 无 XFF 头，直接返回 remote_addr
    local xff = ngx.var.http_x_forwarded_for
    if not xff or xff == "" then
        return remote_addr
    end
    
    -- 按逗号分割，取最左侧（客户端真实 IP 应在最左）
    -- 注意：某些配置下真实 IP 在最右，可通过配置调整
    local ip_chain = {}
    for ip in string.gmatch(xff, "[^,%s]+") do
        table.insert(ip_chain, ip)
    end
    
    -- 默认策略：从最左开始，第一个非内网/非信任代理的 IP
    for _, ip in ipairs(ip_chain) do
        -- 基础格式校验
        if not string.match(ip, "^%d+%.%d+%.%d+%.%d+$") and 
           not string.match(ip, "^[%x:]+") then
            goto continue
        end
        
        -- 跳过信任代理
        local is_trusted = false
        for _, cidr in ipairs(trusted_proxies) do
            if _M.ip_in_cidr(ip, cidr) then
                is_trusted = true
                break
            end
        end
        
        if not is_trusted then
            return ip
        end
        
        ::continue::
    end
    
    -- 全是信任代理，返回 remote_addr
    return remote_addr
end

-- 设置信任代理（在 config.lua 中调用）
function _M.set_trusted_proxies(proxies)
    trusted_proxies = proxies or {}
end

-- ============================================================
-- 2. CIDR 网段匹配
-- ============================================================

local bit = require "bit"

local function ip_to_number(ip)
    local o1, o2, o3, o4 = string.match(ip, "^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not o1 then return nil end
    return (tonumber(o1) * 16777216) + (tonumber(o2) * 65536) + 
           (tonumber(o3) * 256) + tonumber(o4)
end

function _M.ip_in_cidr(ip, cidr)
    local ip_num = ip_to_number(ip)
    if not ip_num then return false end
    
    local net, mask_bits = string.match(cidr, "^(.-)/(%d+)$")
    if not net then
        -- 精确匹配
        return ip == cidr
    end
    
    local net_num = ip_to_number(net)
    if not net_num then return false end
    
    mask_bits = tonumber(mask_bits)
    local mask = bit.lshift(0xFFFFFFFF, 32 - mask_bits)
    mask = bit.band(mask, 0xFFFFFFFF)
    
    return bit.band(ip_num, mask) == bit.band(net_num, mask)
end

-- 检查 IP 是否在列表中（支持 CIDR）
function _M.ip_in_list(ip, list)
    if not list or #list == 0 then return false end
    for _, item in ipairs(list) do
        if _M.ip_in_cidr(ip, item) then
            return true
        end
    end
    return false
end

-- ============================================================
-- 3. 请求分类（静态文件 / 动态请求 / 上传 / API）
-- ============================================================

-- 静态文件扩展名映射
local static_extensions = {
    -- 图片
    png = true, jpg = true, jpeg = true, gif = true, svg = true, 
    ico = true, bmp = true, webp = true, apng = true,
    -- 字体
    woff = true, woff2 = true, ttf = true, eot = true, otf = true,
    -- CSS/JS（注意：JS 也可能是 API 返回，需结合路径判断）
    css = true, less = true, scss = true,
    -- 媒体
    mp4 = true, webm = true, ogv = true, mp3 = true, ogg = true, 
    wav = true, flac = true, aac = true,
    -- 文档/其他静态
    pdf = true, xml = true, txt = true, md = true,
    -- 压缩包（静态下载）
    zip = true, gz = true, tar = true, bz2 = true, ["7z"] = true,
}

-- API 路径特征（用于排除）
local api_patterns = {
    "^/api/", "^/ajax/", "^/rest/", "^/graphql", "^/v%d+/",
    "^/ws/", "^/rpc/", "^/svc/",
}

function _M.classify_request()
    local uri = ngx.var.uri or "/"
    local method = ngx.req.get_method() or "GET"
    local content_type = ngx.var.http_content_type or ""
    
    -- 1. 上传请求
    if string.find(content_type, "multipart/form-data", 1, true) then
        return "upload"
    end
    
    -- 2. 检查是否是 API 路径（即使后缀是 json 也认为是动态）
    for _, pattern in ipairs(api_patterns) do
        if ngx.re.match(uri, pattern, "ijo") then
            return "api"
        end
    end
    
    -- 3. 检查后缀
    local ext = string.match(uri, "%.([a-zA-Z0-9]+)$")
    if ext then
        ext = string.lower(ext)
        if static_extensions[ext] then
            -- 对 js/json 做额外判断：常见静态资源路径
            if ext == "js" or ext == "json" then
                if string.match(uri, "^/static/") or 
                   string.match(uri, "^/assets/") or
                   string.match(uri, "^/dist/") or
                   string.match(uri, "^/js/") or
                   string.match(uri, "^/resources/") then
                    return "static"
                end
                -- 否则可能是 API 返回的 JS/JSON
                return "api"
            end
            return "static"
        end
    end
    
    -- 4. 常见静态资源路径（无后缀或查询参数干扰）
    if string.match(uri, "^/static/") or
       string.match(uri, "^/assets/") or
       string.match(uri, "^/dist/") or
       string.match(uri, "^/images/") or
       string.match(uri, "^/img/") or
       string.match(uri, "^/css/") or
       string.match(uri, "^/fonts/") then
        return "static"
    end
    
    -- 5. 默认动态请求
    return "dynamic"
end

-- ============================================================
-- 4. 多重解码链（防御编码绕过）
-- ============================================================

function _M.url_decode(str)
    if not str then return "" end
    return ngx.unescape_uri(str)
end

function _M.html_decode(str)
    if not str then return "" end
    local entities = {
        ["&amp;"] = "&", ["&lt;"] = "<", ["&gt;"] = ">",
        ["&quot;"] = '"', ["&#x27;"] = "'", ["&#x2F;"] = "/",
        ["&#39;"] = "'", ["&#47;"] = "/",
    }
    for enc, dec in pairs(entities) do
        str = string.gsub(str, enc, dec)
    end
    return str
end

function _M.decode_chain(str, depth)
    depth = depth or 3  -- 默认最多解码 3 层
    local prev = str
    for i = 1, depth do
        local decoded = _M.url_decode(prev)
        decoded = _M.html_decode(decoded)
        -- 额外：处理 \xNN 编码
        decoded = string.gsub(decoded, "\\x(%x%x)", function(h)
            return string.char(tonumber(h, 16))
        end)
        -- 额外：处理 \uNNNN 编码
        decoded = string.gsub(decoded, "\\u(%x%x%x%x)", function(h)
            local n = tonumber(h, 16)
            if n < 128 then
                return string.char(n)
            end
            return "\\u" .. h  -- 保持原样（Unicode 简化处理）
        end)
        
        if decoded == prev then
            break  -- 无变化，停止解码
        end
        prev = decoded
    end
    return prev
end

-- ============================================================
-- 5. Bot 特征检测（轻量级）
-- ============================================================

function _M.bot_signals()
    local signals = {}
    local headers = ngx.req.get_headers()
    local ua = ngx.var.http_user_agent or ""
    local referer = ngx.var.http_referer or ""
    local cookie = ngx.var.http_cookie or ""
    
    -- 信号 1: 无 User-Agent
    if ua == "" then
        signals.no_ua = true
    end
    
    -- 信号 2: 无 Referer（首次访问除外，但静态资源通常应有 Referer）
    if referer == "" then
        signals.no_referer = true
    end
    
    -- 信号 3: 无 Accept 头（或过于宽泛）
    local accept = headers["accept"] or ""
    if accept == "" or accept == "*/*" then
        signals.no_accept = true
    end
    
    -- 信号 4: 无 Accept-Language
    local accept_lang = headers["accept-language"] or ""
    if accept_lang == "" then
        signals.no_lang = true
    end
    
    -- 信号 5: 无 Cookie（非首次访问场景下）
    if cookie == "" then
        signals.no_cookie = true
    end
    
    -- 信号 6: UA 包含明显自动化特征（除已配置黑名单外）
    local auto_patterns = {
        "curl", "wget", "python", "java", "go-http", "httpclient",
        "libwww", "scrapy", "phantomjs", "selenium", "headless",
    }
    ua = string.lower(ua)
    for _, pat in ipairs(auto_patterns) do
        if string.find(ua, pat, 1, true) then
            signals.automation_ua = true
            break
        end
    end
    
    -- 计算风险分
    local score = 0
    if signals.no_ua then score = score + 3 end
    if signals.no_referer then score = score + 1 end
    if signals.no_accept then score = score + 1 end
    if signals.no_lang then score = score + 1 end
    if signals.no_cookie then score = score + 1 end
    if signals.automation_ua then score = score + 3 end
    
    signals.score = score
    signals.risk_level = score >= 5 and "high" or (score >= 3 and "medium" or "low")
    
    return signals
end

-- ============================================================
-- 6. 请求指纹（用于 CC 计数去重/识别）
-- ============================================================

function _M.request_fingerprint()
    local ip = _M.get_real_ip()
    local uri = ngx.var.uri or "/"
    local ua = ngx.var.http_user_agent or ""
    -- 简化的指纹：IP + URI（去除查询参数）+ UA 前 20 字符
    local base = uri
    local qm = string.find(base, "?", 1, true)
    if qm then
        base = string.sub(base, 1, qm - 1)
    end
    local ua_short = string.sub(ua, 1, 20)
    return ip .. "|" .. base .. "|" .. ua_short
end

return _M
