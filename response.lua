require 'init'
local cache = require "cache"
local utils = require "utils"

-- 防御性兜底：init_by_lua 阶段可能未正确加载 attacklog
if attacklog == nil or attacklog == false then
    attacklog = true
end

local client_ip = getClientIp and getClientIp() or (ngx.var.remote_addr or "unknown")
local request_uri = ngx.var.request_uri or "/"
ngx.log(ngx.ERR, "WAF_RESPONSE: ip=", client_ip, " uri=", request_uri, " status=", ngx.var.status or "-")
response_filter()
