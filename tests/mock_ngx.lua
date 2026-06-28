-- 最小化的 ngx 模拟对象，用于在 resty/luajit 之外运行单元测试
local _M = {}

_M.now = function() return os.time() end
_M.time = function() return os.time() end
_M.today = function() return os.date("%Y-%m-%d") end
_M.localtime = function() return os.date("%Y-%m-%dT%H:%M:%S") end

_M.log = function(level, ...)
    local args = {...}
    local msg = ""
    for _, v in ipairs(args) do
        msg = msg .. tostring(v)
    end
    -- 测试时只输出 ERR 级别日志
    if level == _M.ERR or level == _M.WARN then
        print("[ngx.log] " .. msg)
    end
end

_M.NOTICE = 1
_M.WARN = 2
_M.ERR = 3
_M.HTTP_INTERNAL_SERVER_ERROR = 500
_M.HTTP_FORBIDDEN = 403
_M.HTTP_NOT_FOUND = 404

-- 模拟 ngx.re.compile 和 ngx.re.match
_M.re = {
    compile = function(pattern, options)
        -- 简单校验：尝试用 ngx.re.match 空串来验证
        local ok, res = pcall(function()
            -- 这里在真实 ngx 环境下是 C 函数，测试环境无法完整模拟
            return { pattern = pattern, options = options }
        end)
        if not ok then
            error(res)
        end
        return res
    end,
    match = function(subject, pattern, options)
        -- 测试环境下简单返回 nil，真实测试应使用更完整的模拟
        return nil
    end
}

_M.shared = {}

_M.var = {}

return _M
