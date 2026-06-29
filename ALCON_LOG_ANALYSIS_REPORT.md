# www.alcon.cn 日志分析报告

> 分析对象：`D:\lumin\desktop\www.alcon.cn.log`
> 分析时间：2026-06-29
> WAF 版本：ngx-lua-waf（当前工作目录）

## 一、整体情况

| 分类 | 数量 | 说明 |
|------|------|------|
| 总请求数 | 242 | 日志文件中所有有效 HTTP/畸形请求 |
| 正常/白名单 | 68 | 浏览器访问首页、静态资源（/_next/static/）、/h5/、/logo.png 等 |
| **已被 WAF 规则覆盖（将拦截）** | **154** | 命中 UA/Method/Traversal/URL/Dangerous/Args/FileExt 规则 |
| Nginx 层直接拒绝 | 20 | TLS 握手发到 HTTP 端口、挖矿协议、空请求、畸形 HTTP 等 |
| 日志显示已拦截但规则未命中 | 0 | 之前 2 条（POST / 413、GET / 431）分别为 BodyLimit 与 Nginx Header 过大 |
| **疑似漏网** | **0** | 补充规则后，所有明显攻击/恶意请求均被覆盖 |

**结论：当前规则（含本次补充）可覆盖日志中所有明显的攻击、扫描、恶意爬取请求。**

---

## 二、攻击类型分布

| 攻击类型 | 数量 | 命中规则 |
|----------|------|----------|
| libredtail 扫描 | 42 | UA 黑名单 |
| .env 配置文件泄露探测 | 28 | dangerous[core] `\.env...` |
| Go-http-client 探测 | 11 | UA 黑名单 |
| zgrab 扫描 | 10 | UA 黑名单 |
| URL 黑名单（含本次新增） | 6 | url 规则 |
| 路径穿越 | 6 | traversal 规则 |
| Umai-Scanner 扫描 | 6 | UA 黑名单 |
| PaloAlto/Cortex Xpanse 扫描 | 5 | UA 黑名单 |
| 危险 HTTP 方法/非标准协议 | 4 | method 规则 |
| curl 探测 | 4 | UA 黑名单 |
| Shodan 扫描 | 2 | UA 黑名单 |
| masscan 扫描 | 2 | UA 黑名单 |
| FreePBX 扫描 | 2 | UA 黑名单 |
| ModatScanner 扫描 | 2 | UA 黑名单 |
| Node 调试接口探测 | 1 | dangerous[nodejs]（本次新增） |
| Symfony Profiler 探测 | 1 | dangerous[core] `^/_profiler...` |
| 文件扩展名黑名单 | 1 | fileExtCheck |
| 其他 DANGEROUS[core] | 4 | dangerous[core] |

---

## 三、补充的规则

针对日志中 12 条原规则未覆盖的可疑请求，补充了以下规则。

### 1. `wafconf/url`

新增内容：

```regex
# URL 编码的路径混淆探测（如下划线编码为 %5f 的 _next 静态资源路径）
/%5[fF][nN][eE][xX][tT]

# Cobalt Strike / 常见 C2 信标与下载路径
^/(?:WuEL|SiteLoader|mPlayer|stager64)(?:[/?#]|$)
^/download/file\.ext(?:[/?#]|$)
```

**覆盖的请求：**
- `/%5fnext/static/chunks/...` 等 6 条编码下划线静态资源探测
- `/WuEL`、`/SiteLoader`、`/mPlayer` 等 C2 信标路径
- `/download/file.ext` Cobalt Strike 默认下载路径

### 2. `wafconf/dangerous`（[nodejs] 分组）

新增内容：

```regex
# Node.js 调试接口（Node --inspect / JetBrains WebStorm 调试代理）
^/json/serverinfo(?:/.*)?$
```

**覆盖的请求：**
- `172.177.3.78 GET /json/serverinfo/*`（JetBrains/WebStorm 调试端点探测）

### 3. `config.lua`

新增恶意 IP：

```lua
ipBlocklist={"1.0.0.1","162.216.150.244","185.213.175.171"}
```

**覆盖的请求：**
- `185.213.175.171` 全量请求（该 IP 先发送挖矿协议、再 POST /、再访问 C2 路径，整体为恶意行为）
- 特别是 `/a` 这种单字符路径，直接封禁会误伤正常业务，因此通过 IP 黑名单解决

---

## 四、验证结果

### 1. 规则语法校验

```bash
python tests/validate_rules.py
```

结果：

```
[OK] args                 valid=106 invalid=  0
[OK] cookie               valid= 21 invalid=  0
[OK] dangerous            valid=368 invalid=  0
[OK] header               valid= 13 invalid=  0
[OK] method               valid=  3 invalid=  0
[OK] post                 valid= 88 invalid=  0
[OK] referer              valid=  1 invalid=  0
[OK] response             valid= 36 invalid=  0
[OK] url                  valid= 12 invalid=  0
[OK] user-agent           valid=  8 invalid=  0
[OK] whiteurl             valid=  4 invalid=  0
------------------------------------------------------------
Total: valid=660 invalid=0
```

所有规则正则语法有效。

### 2. 日志覆盖验证

补充规则后，分析脚本输出：

```
总请求数: 242
  - 正常/白名单: 68
  - 已被规则覆盖（将拦截）: 154
  - 日志中已显示被拦截但规则未命中: 0
  - Nginx 层直接拒绝（畸形/TLS/空请求）: 20
  - 疑似漏网（可疑但未命中规则）: 0
  - 无法解析: 0
```

---

## 五、近期 CVE 补充规则（2025-2026）

针对 alcon.cn 使用的 **Next.js / React** 技术栈以及当前公开的高危 CVE，额外补充了以下规则：

### 1. `wafconf/header` — Next.js Middleware Bypass (CVE-2025-29927)

```regex
^x-middleware-subrequest:
^x-middleware-override-headers:
```

- **漏洞**：Next.js 外部请求携带内部头 `x-middleware-subrequest` 可跳过中间件鉴权。
- **规则**：直接拦截外部请求中的 Next.js 内部中间件头，外部用户不应发送。
- **影响版本**：Next.js 11.1.4–15.2.2

### 2. `wafconf/post` — React2Shell / RSC 反序列化 (CVE-2025-55182 / CVE-2025-66478) 与 RSC DoS (CVE-2026-23870)

```regex
"status"\s*:\s*"resolved_model"
"_response"\s*:\s*\{\s*"_prefix"
"_formData"\s*:\s*\{\s*"get"\s*:\s*"\$\d+:(?:constructor|__proto__)
\$\d+:(?:constructor|__proto__):(?:constructor|then)
process\.mainModule\.require\s*\(\s*['"]child_process['"]\s*\)
vm#runIn(?:This|New)Context
\$@\d+
```

- **漏洞**：React Server Components Flight 协议反序列化不可信数据，导致预认证 RCE（React2Shell）或 DoS。
- **规则**：检测 POST body 中的异常 Flight payload 特征（`resolved_model`、`_response._prefix`、原型污染链、`child_process` 等）。
- **注意**：未在 header 层直接封禁 `Next-Action` / `rsc-action-id`，因为正常 Server Actions 也会使用这些头，直接 block 误伤高。

### 3. 其他近期 CVE 评估

| CVE | 目标 | WAF 可拦截性 | 说明 |
|-----|------|--------------|------|
| CVE-2025-29927 | Next.js | ✅ 已补充 | Header 层拦截内部中间件头 |
| CVE-2025-55182 / CVE-2025-66478 | React/Next.js RSC | ✅ 已补充 | POST body 检测异常 Flight payload |
| CVE-2026-23870 / CVE-2026-23869 | React/Next.js RSC | ✅ 部分补充 | 同 React2Shell 检测 + CC 限速 |
| CVE-2026-27978 | Next.js Server Actions CSRF | ⚠️ 不推荐 | `Origin: null` 绕过，需业务层 CSRF Token |
| CVE-2026-29057 | Next.js rewrite 请求走私 | ⚠️ 部分 | 依赖 chunked TE 检测，header 已有请求走私规则 |
| CVE-2025-15566 / CVE-2026-3288 | ingress-nginx | ❌ 不可拦截 | K8s Ingress 注解配置注入，非 HTTP 层面 |
| CVE-2026-41940 | cPanel/WHM | ❌ 不可拦截 | 认证绕过，需应用层补丁 |
| CVE-2026-9082 | Drupal PostgreSQL SQLi | ✅ 已有覆盖 | args/post 中 SQLi 规则可覆盖 |
| CVE-2026-45247 | Magento PHP 对象注入 | ✅ 已有覆盖 | args/post 中反序列化规则可覆盖 |
| CVE-2026-40175 | Axios 原型污染 | ✅ 已有覆盖 | args 中已有原型污染检测 |
| CVE-2025-64459 | Django SQL 注入 | ✅ 已有覆盖 | args/post 中 SQLi 规则可覆盖 |
| CVE-2025-31125 | Vite WASM Path Traversal | ✅ 已有覆盖 | traversal/args 规则可覆盖 |
| CVE-2025-66614 / CVE-2026-24733 | Tomcat | ⚠️ 有限 | HTTP/0.9 与 SNI 层，WAF 难以覆盖 |

---

## 六、仍需注意的非 WAF 场景

以下请求由 Nginx 本身拒绝，不属于 WAF 规则覆盖范围，但已在边缘被拦截：

| 特征 | 状态码 | 说明 |
|------|--------|------|
| TLS ClientHello 发到 80 端口 | 400 | `\x16\x03\x01...` |
| RDP / MS-TDS 等二进制协议 | 400 | `\x03\x00\x00...` |
| 挖矿协议请求体 | 400 | `mining.subscribe`、`eth_submitLogin` 等 |
| 空请求行 | 400 | `""` |
| 请求头过大 | 431 | Nginx `large_client_header_buffers` 限制 |
| POST Body 超过 10MB | 413 | WAF BodyLimit（会写入 sec.log） |

---

## 七、建议

1. **开启 CC 增强防御**：日志中存在大量扫描器高频探测，建议 `CCEnhanced = "on"`，并观察静态资源无 Referer 阈值。
2. **监控 POST / 异常行为**：`185.213.175.171` 的 POST / 请求在 access log 中无 body 内容，建议检查后端是否已记录该 IP 的 POST payload。
3. **定期更新 IP 黑名单**：可将本次发现的扫描器 IP（如 `185.213.175.171`）加入持久化黑名单。
4. **开启 Response 检测**：当前 `ResponseAction = "log"`，建议观察一段时间无异常后，根据业务情况决定是否改为 `block`。
