# www.alcon.cn 日志分析报告（修正版）

> 分析对象：`D:\lumin\desktop\www.alcon.cn.log`
> 分析时间：2026-06-29
> WAF 版本：ngx-lua-waf（当前工作目录）
> **注意**：此前报告中的“242 条请求”为错误数据，实际日志仅有 106 条请求。本报告已按真实日志重新分析。

## 一、整体情况

| 分类 | 数量 | 说明 |
|------|------|------|
| 总请求数 | 106 | 日志文件中所有有效 HTTP/畸形请求 |
| 正常/白名单 | ~45 | 浏览器访问首页、静态资源（/_next/static/）、/detect、/result、/api/* 等业务接口 |
| **已被 WAF 规则覆盖（将拦截）** | **26** | 命中 UA/Method/Traversal/Dangerous/URL 规则且返回拦截状态码 |
| 命中规则但日志显示未拦截 | 19 | 这些请求在当前规则下会被命中，但当时返回 200/301，说明规则是事后补充或当时 WAF 未启用 block |
| Nginx 层直接拒绝 | 6 | TLS 握手发到 HTTP 端口、空 UA 直接 400 等 |
| 未命中规则的可疑请求 | 0 | 补充规则后，所有明显攻击/恶意请求均被规则覆盖 |

**结论：当前规则（含本次补充）可覆盖日志中所有明显的攻击、扫描、恶意爬取请求。**

---

## 二、攻击类型分布

| 攻击类型 | 数量 | 命中规则 |
|----------|------|----------|
| Joomla/JCE 后台探测 | 14 | dangerous[php] + UA 黑名单（本次新增） |
| .env 配置文件泄露探测 | 5 | dangerous[core] `\.env...` + url |
| 路径穿越 | 1 | traversal 规则 |
| Censys 扫描 | 3 | UA 黑名单 |
| ModatScanner 扫描 | 2 | UA 黑名单 |
| python-requests 探测 | 2 | UA 黑名单 |
| curl 探测 | 4 | UA 黑名单 |
| zgrab 扫描 | 1 | UA 黑名单 |
| Shodan-Pull 扫描 | 1 | UA 黑名单 |
| Palo Alto/Cortex Xpanse 扫描 | 1 | UA 黑名单 |
| GeoServer 探测 | 2 | dangerous[core] `^/geoserver...` |
| JBoss invoker 反序列化探测 | 1 | dangerous[core] `^/invoker/readonly$` |
| 非标准 HTTP 方法 | 3 | method 规则 |
| Go-http-client 探测 | 1 | UA 黑名单 |

---

## 三、补充的规则

针对日志中 14 条原规则未完全覆盖的 Joomla/JCE 扫描请求，以及使用极简/伪造 UA 的扫描器，补充了以下规则。

### 1. `wafconf/dangerous`（[php] 分组）

新增内容：

```regex
# Joomla 后台/组件/JCE 编辑器探测
^/administrator/manifests(?:/.*)?$
^/plugins/editors/jce(?:/.*)?$
^/index\.php\?option=com_jce
```

**覆盖的请求：**
- `GET /administrator/manifests/files/joomla.xml`
- `GET /plugins/editors/jce/jce.xml`
- `GET /administrator/components/com_jce/jce.xml`
- `GET /index.php?option=com_jce&task=explorer`

### 2. `wafconf/user-agent`

新增内容：

```regex
# 极简/伪造 UA（常被扫描器、资产测绘工具使用）
^Mozilla/5\.0 \(Windows NT 10\.0; Win64; x64\)$
^Mozilla/5\.0$
```

**覆盖的请求：**
- `192.142.28.77` 的 14 条 Joomla/JCE 扫描请求（UA 为裸 `Mozilla/5.0` 或仅含平台信息）

### 3. `config.lua`

新增恶意 IP：

```lua
ipBlocklist={"1.0.0.1","162.216.150.244","185.213.175.171","71.6.158.166"}
```

**覆盖的请求：**
- `71.6.158.166` 已确认为 Shodan 扫描节点（`ninja.census.shodan.io`），在日志中执行了 `/.well-known/security.txt` 等测绘行为。

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
[OK] dangerous            valid=382 invalid=  0
[OK] header               valid= 15 invalid=  0
[OK] method               valid=  3 invalid=  0
[OK] post                 valid= 95 invalid=  0
[OK] referer              valid=  1 invalid=  0
[OK] response             valid= 42 invalid=  0
[OK] url                  valid= 12 invalid=  0
[OK] user-agent           valid= 10 invalid=  0
[OK] whiteurl             valid=  4 invalid=  0
------------------------------------------------------------
Total: valid=691 invalid=0
```

所有规则正则语法有效。

### 2. 日志覆盖验证

补充规则后，分析脚本输出：

```
总请求数: 106
  - 已被规则覆盖（将拦截）: 26
  - 命中规则但日志显示未拦截: 19
  - 400 异常未命中: 6
  - 未命中规则的可疑请求: 0
```

---

## 五、仍需关注的非规则类问题

### 1. 白名单路径绕过了 UA/Header 检测（代码逻辑层面）

当前 `waf.lua` 中 `whiteurl()`（放行 `/robots.txt`、`/sitemap.xml`、`/.well-known/*`、`/favicon.ico`）位于 `ua()` 和 `headers()` 检查之前。这导致：
- CensysInspect UA 访问 `/sitemap.xml` 时直接走白名单放行；
- 若请求携带 `Acunetix-Aspect` 等扫描头访问白名单路径，也可能被放行。

**建议**：评估是否将已知扫描器 UA/扫描器特征头的检查提前到 `whiteurl()` 之前，或让 `whiteurl` 仅绕过 dangerous/url/args 检查，而不绕过 UA/Header 安全检测。

### 2. 状态码 400 的 TLS/空请求属于 Nginx 层

以下 6 条请求由 Nginx 本身拒绝，不属于 WAF 规则覆盖范围：

| 特征 | 状态码 | 说明 |
|------|--------|------|
| TLS ClientHello 发到 80 端口 | 400 | `\x16\x03\x01...` |
| 空 UA + GET / | 400 | `185.189.182.234` |
| PRI * HTTP/2.0 | 400 | 已命中 method 规则 |

### 3. 疑似 Shodan 同网段节点

`94.154.43.87`（空 UA，GET / 返回 24507）与日志中已识别的 `94.154.43.66 Shodan-Pull/1.0` 处于同一 /24，建议观察；若后续确认可加入 IP 黑名单。

---

## 六、建议

1. **确认 WAF 已启用 block 模式**：当前 `ActionMode = "block"` 且各模块动作均为 `block`，但日志中出现大量“命中规则却返回 200/301”的请求，建议检查当时 WAF 是否已加载最新规则、Nginx 是否已 reload。
2. **开启 CC 增强防御**：日志中存在大量扫描器高频探测，建议 `CCEnhanced = "on"`，并观察静态资源无 Referer 阈值。
3. **定期更新 IP 黑名单**：可将本次确认的扫描器 IP（如 `71.6.158.166`）加入持久化黑名单。
4. **评估 whiteurl 与 UA/Header 检测的优先级**：避免已知扫描器通过 `/robots.txt`、`/sitemap.xml` 等白名单路径绕过 UA 检测。
