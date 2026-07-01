# alcon.lumaicare.com 日志 WAF 规则补充报告

> 分析对象：`D:\lumin\desktop\alcon.lumaicare.com.log`  
> 分析时间：2026-07-01  
> WAF 版本：ngx-lua-waf（当前工作目录）

## 一、分析结论

对日志进行解析与规则命中验证后，发现以下未被现有规则覆盖的恶意/探测请求模式：

| 攻击面 | 典型请求 | 风险说明 |
|--------|---------|---------|
| LLM / OpenAI API 探测 | `GET /v1/models`、`GET /v1/embeddings` | 非 AI 站点探测 OpenAI 兼容接口 |
| AI 工具客户端探测 | `POST /mcp`、`GET /sse`（UA: python-httpx） | MCP / SSE 端点扫描 |
| C2 / 随机信标路径 | `/Ajx3wTA89968`、`/Dr0v`、`/jMRS`、`/SGUn`、`/aab8` | Cobalt Strike 或扫描器随机路径 |
| CMS / 后台 / 脚本探测 | `/xxxss`、`/baker.php`、`/1234.php`、`/api.php?s=...`、`/index.php/store/passport/login`、`/admin-api/system/auth/get-permission-info`、`/assets/js/fast.js` | 常见 CMS、后台、入口探测 |
| VPN / 远程接入探测 | `POST /vpnsvc/connect.cgi`、`HEAD /epa/scripts/win/nsepa_setup.exe` | Citrix NetScaler / SSL VPN 探测 |
| 单字符伪造 UA | UA = `M` | 配合随机路径，疑似 C2 信标 |

原有规则已覆盖 `.env`、`.git/config`、`/nacos`、`/api/auth`、`/owa` 等大部分探测，但日志中这些请求因返回 `301/308` 未实际被拦截（多为 HTTP→HTTPS 重定向阶段或当时 WAF 未开启 block），本次重点补充**规则缺口**。

## 二、补充的规则

### 1. `wafconf/user-agent`

```regex
# [UA2] 常见爬虫 / 数据采集（新增 python-httpx）
(cdn-detect|SemrushBot|pyspider|Scrapy|python-requests|python-httpx|Python-urllib|HTTrack|harvest|Parser|libwww|BBBike|PycURL|zmeu|BabyKrokodil|httperf|SF/|Office)

# [UA7] 单字符伪造 UA
^M$
```

**覆盖请求：**
- `/mcp`、`/sse`（python-httpx）
- `/Ajx3wTA89968?...`（UA = `M`）

### 2. `wafconf/url`

```regex
# [U6] Cobalt Strike / C2 随机信标路径（扩展 observed 样本）
^/(?:Dr0v|aaa9|aab[89]|jMRS|SGUn|Ajx3wTA89968)$

# [U3/U4] CMS / 后台 / 脚本探测路径（日志中新发现）
^/xxxss$
^/assets/js/fast\.js$
^/index\.php/store/passport/login$
^/admin-api/system/auth/get-permission-info$
^/api\.php\?s=
^/(?:baker|1234)\.php$
^/config\.dev\.php$
```

**覆盖请求：**
- `/Dr0v`、`/jMRS`、`/SGUn`、`/aab8`、`/Ajx3wTA89968`
- `/xxxss`、`/assets/js/fast.js`、`/index.php/store/passport/login`
- `/admin-api/system/auth/get-permission-info`、`/api.php?s=article/datalist`
- `/baker.php`、`/1234.php`、`/config.dev.php`

### 3. `wafconf/dangerous`

```regex
# [ai]
# [D24] AI / LLM 服务 API 探测（非 AI 站点的 OpenAI 兼容接口扫描）
^/v1/(?:models|embeddings|chat/completions|completions|images|audio|files|fine-tunes|batches|assistants|threads|vector_stores|moderations|realtime)$

# [vpn]
# [D29] VPN / 远程接入设备探测
^/vpnsvc/connect\.cgi$
^/epa/scripts/win/nsepa_setup\.exe$
```

**覆盖请求：**
- `/v1/models`、`/v1/embeddings`
- `/vpnsvc/connect.cgi`、`/epa/scripts/win/nsepa_setup.exe`

### 4. `wafconf/RULE_CLASSIFICATION.md`

- 更新 `D24` 示例为正则全量写法
- 新增 `D29` VPN / 远程接入设备探测分类
- 更新 `UA7` 说明，纳入单字符伪造 UA

## 三、验证结果

### 1. 规则语法校验

```bash
python tests/validate_rules.py
```

结果：

```
[OK] args                 valid=106 invalid=  0
[OK] cookie               valid= 21 invalid=  0
[OK] dangerous            valid=385 invalid=  0
[OK] header               valid= 15 invalid=  0
[OK] method               valid=  3 invalid=  0
[OK] post                 valid= 95 invalid=  0
[OK] referer              valid=  1 invalid=  0
[OK] response             valid= 42 invalid=  0
[OK] url                  valid= 20 invalid=  0
[OK] user-agent           valid= 11 invalid=  0
[OK] whiteurl             valid=  4 invalid=  0
------------------------------------------------------------
Total: valid=703 invalid=0
```

### 2. 恶意模式覆盖验证

从原日志中提取 19 条未拦截的恶意请求构造测试集，补充规则后 `analyze_access_log.py` 输出：

```
总请求数: 19
  - 已被规则覆盖（将拦截）: 19
  - 日志中已显示被拦截但规则未命中: 0
  - Nginx 层直接拒绝: 0
  - 疑似漏网（可疑但未命中规则）: 0
```

所有新发现的恶意模式均被规则覆盖。

## 四、注意事项

1. **301/308 状态码问题**：日志中大量恶意请求返回 `301/308`，说明它们触发了 Nginx HTTP→HTTPS 重定向，未进入 WAF block 阶段。补充的规则在 HTTPS 流量到达 WAF 时会生效，但建议检查 Nginx 配置，确保 HTTP 请求同样经过 WAF 或直接被拒绝。
2. **单字符 UA 规则 `^M$`**：误伤极低，但如遇特殊客户端（如极简 IoT 设备）可评估调整。
3. **`/api\.php\?s=` 规则**：针对日志中 PbootCMS 类探测 `s=article/datalist`，若业务 legitimately 使用 `/api.php?s=...` 请加入 `whiteurl` 放行。
4. 规则文件已按 `# [分类编号]` 规范注释，便于后续审计与按场景启用。
