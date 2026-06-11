local _M = {}

function _M.set_ttl(ttl)
end

function _M.read_rule_cached(rulepath, var, force_reload)
    local filepath = rulepath .. var
    local file, err = io.open(filepath, "r")
    if not file then
        ngx.log(ngx.WARN, "WAF: failed to open rule file: ", filepath, " error: ", err or "unknown")
        return nil
    end
    
    local t = {}
    for line in file:lines() do
        line = string.gsub(line, "\r$", "")
        if line ~= "" and string.sub(line, 1, 1) ~= "#" then
            table.insert(t, line)
        end
    end
    file:close()
    return t
end

function _M.read_tagged_rule_cached(rulepath, var, force_reload)
    local filepath = rulepath .. var
    local file, err = io.open(filepath, "r")
    if not file then
        ngx.log(ngx.WARN, "WAF: failed to open tagged rule file: ", filepath, " error: ", err or "unknown")
        return nil
    end
    
    local t = {}
    local current_tag = "common"
    for line in file:lines() do
        line = string.gsub(line, "\r$", "")
        if line ~= "" then
            local tag = string.match(line, "^# %[(%%w+)%]")
            if tag then
                current_tag = tag
            elseif string.sub(line, 1, 1) ~= "#" then
                table.insert(t, { tag = current_tag, rule = line })
            end
        end
    end
    file:close()
    return t
end

function _M.match_cached(text, pattern, options)
    if not text or text == "" or not pattern or pattern == "" then
        return nil
    end
    return ngx.re.match(text, pattern, options or "isjo")
end

function _M.reload_all()
    ngx.log(ngx.NOTICE, "WAF: rules reloaded (no-op in cache-less mode)")
end

function _M.reload_file(rulepath, var)
end

function _M.get_stats()
    return { rule_files = 0, tagged_rule_files = 0, regex_patterns = 0, ttl = 0 }
end

return _M
