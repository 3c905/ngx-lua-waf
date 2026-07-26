require 'init'
local cache = require "cache"
local utils = require "utils"

-- 防御性兜底：init.lua 若被二次执行（require 'init' 重入），同名布尔
-- 开关会被 optionIsOn 翻转为 false；init.lua 末尾已通过
-- package.loaded["init"]=true 根治，此处仅作最后防线
if attacklog == nil or attacklog == false then
    attacklog = true
end

local client_ip = getClientIp and getClientIp() or (ngx.var.remote_addr or "unknown")
local request_uri = ngx.var.request_uri or "/"
waf_debug("WAF_RESPONSE: ip=", client_ip, " uri=", request_uri, " status=", ngx.var.status or "-")
response_filter()
