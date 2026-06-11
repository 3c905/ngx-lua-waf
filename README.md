# ngx-lua-waf

基于 OpenResty / Nginx + Lua 的轻量级 Web 应用防火墙，在原版 ngx_lua_waf 基础上合并了 `block-dangerous.conf` 的敏感路径/文件屏蔽能力，并新增**增强版 CC 防御**、**规则缓存**、**XFF 真实 IP 解析**、**CIDR 网段支持**、**Bot 信号检测**、**渐进式惩罚**、**按模块告警模式**、**命令行管理工具**等能力，形成与主流 WAF 对齐的多层防御体系。

---

## 功能特性

| 防护模块 | 说明 |
|---------|------|
| **IP 黑白名单** | 支持精确 IP 和 CIDR 网段（如 `10.0.0.0/8`） |
| **CC 攻击防护** | 原版简单计数器 + **增强版三级分级限速**（全局 / 静态文件 / 动态请求） |
| **CC 渐进惩罚** | 503 → Cookie 挑战验证 → 临时封禁 → 长期封禁 |
| **Bot 信号检测** | UA / Referer / Cookie / Accept 多维评分，联动调整 CC 阈值 |
| **静态文件专项 CC** | 自动识别 `.js` `.css` `.png` 等静态资源，无 Referer/Cookie 时自动收紧 |
| **URL 黑名单** | 拦截已知恶意路径（SQL 注入、LFI 等） |
| **参数检查** | GET/POST 参数攻击特征检测，支持**多重解码链**防御编码绕过 |
| **User-Agent 黑名单** | 拦截扫描器、爬虫、恶意 UA |
| **Cookie 检查** | Cookie 中的攻击载荷检测 |
| **文件上传检查** | 黑名单扩展名拦截 |
| **敏感路径屏蔽** | 合并 `block-dangerous.conf`，覆盖 Git/IDE/Actuator/Swagger/密钥/凭证/备份等 |
| **技术栈规则** | 按 `[core]` / `[java]` / `[nodejs]` / `[php]` / `[aggressive]` 分组 |
| **HTTP 方法限制** | 禁止 TRACE / TRACK |
| **路径穿越拦截** | 拦截 `../`、`%2e%2e`、空字节 |
| **恶意 Referer** | 拦截 SEO 垃圾流量 |
| **Header 攻击检测** | 请求走私、代理伪造、Header 注入、CRLF、DoS |
| **响应泄露检测** | 错误堆栈、内部路径、数据库连接串、密钥泄露 |
| **规则缓存** | Worker 级缓存 + TTL 刷新，高并发下避免频繁磁盘 IO |
| **正则预编译缓存** | PCRE 正则复用，降低重复编译开销 |
| **日志限流** | 同 IP 同规则 60 秒内可限制记录条数，防日志打爆磁盘 |
| **请求体大小限制** | 默认 10MB 上限，防超大 POST DoS |
| **按模块告警模式** | 各检测模块可独立配置 `block`（拦截）或 `log`（仅记录不拦截） |
| **调试日志开关** | 统一控制所有 `WAF_` 前缀跟踪日志，排查问题时开启，生产环境关闭 |
| **命令行管理工具** | `waf-cli` 通过文件管道管理，无需开放 HTTP 接口 |

---

## 与主流 WAF 的能力对齐

| 能力 | Cloudflare | AWS WAF | ModSecurity | **本项目增强后** |
|------|-----------|---------|-------------|-----------------|
| 请求分类（静态/动态/API） | 自动 | 手动配置 | 规则配置 | 自动 |
| 分级限速 | 支持 | 支持 | 支持 | 支持 |
| Bot 检测 | ML 模型 | CAPTCHA | 基础 | 基础信号评分 |
| 渐进惩罚 | 支持 | 支持 | 基础 | 支持 |
| XFF 真实 IP | 支持 | 支持 | 支持 | 支持 |
| CIDR 支持 | 支持 | 支持 | 支持 | 支持 |
| 规则缓存 | 支持 | 支持 | 支持 | 支持 |
| 威胁情报 | 支持 | 支持 | 无 | 无 |
| 按模块告警模式 | 支持 | 支持 | 基础 | 支持 |
| 分布式 | 全球边缘 | 区域分发 | 单机 | 单机 |

**定位**：本项目增强后，在单机/小集群场景下可达到 AWS WAF + Nginx 原生防护组合 **70-80%** 的 CC 防御能力。大规模分布式场景建议配合 CDN（Cloudflare/阿里云 CDN）使用。

---

## 目录结构

```
ngx-lua-waf/
├── config.lua              # 主配置文件
├── init.lua                # 核心函数库（规则读取、检测函数、日志）
├── waf.lua                 # WAF 入口（Nginx access 阶段调用）
├── response.lua            # 响应过滤入口（Nginx body_filter 阶段调用）
├── block-dangerous.conf    # 原始 Nginx 规则（已合并，可保留备用）
├── install.sh              # 安装脚本（仅供参考，建议手动编译新版）
├── waf-cli                 # 命令行管理工具（unban/banlist/reload/stats）
├── nginx-example.conf      # Nginx 配置示例（含共享字典和管理接口）
├── ANALYSIS.md             # 与主流 WAF 的详细对比分析报告
├── CC_DEFENSE_STRATEGY.md  # CC 防御策略建议（静态文件专项）
├── lib/                    # 增强功能库
│   ├── cache.lua           # 规则缓存 + 正则预编译缓存
│   ├── utils.lua           # 工具函数（XFF/CIDR/请求分类/Bot检测/解码链）
│   └── cc_enhanced.lua     # 增强版 CC 防御引擎
└── wafconf/                # 规则文件目录
    ├── url                 # URL 黑名单（SQLi、LFI 等）
    ├── args                # GET 参数攻击特征
    ├── post                # POST 参数攻击特征
    ├── cookie              # Cookie 攻击特征
    ├── user-agent          # 恶意 UA
    ├── whiteurl            # URL 白名单
    ├── header              # Header 层攻击检测
    ├── response            # 响应敏感信息泄露检测
    ├── dangerous           # 敏感路径/文件/扩展名
    │   ├── # [core]        # 低误伤核心规则（默认开启）
    │   ├── # [java]        # Java 技术栈敏感端点
    │   ├── # [nodejs]      # Node.js 技术栈敏感端点
    │   ├── # [php]         # PHP 技术栈敏感端点
    │   └── # [aggressive]  # 高误伤激进规则（默认关闭）
    ├── referer             # 恶意 Referer
    └── method              # 禁止的 HTTP 方法
```

---

## 快速开始

### 1. Nginx 配置（重要：必须配置共享字典）

在 `nginx.conf` 的 `http` 块中加入共享字典和 Lua 路径：

```nginx
http {
    # 【必须】WAF 共享内存字典
    lua_shared_dict limit      50m;   # 原版 CC 兼容
    lua_shared_dict waf_cc     100m;  # 增强 CC 计数
    lua_shared_dict waf_ban    50m;   # 封禁 IP 列表
    lua_shared_dict waf_cache  10m;   # 规则缓存（可选）

    # Lua 包路径（根据实际路径调整）
    lua_package_path "/path/to/ngx-lua-waf/?.lua;/path/to/ngx-lua-waf/lib/?.lua;;";
    lua_code_cache on;

    server {
        listen 80;
        server_name example.com;

        location / {
            access_by_lua_file /path/to/ngx-lua-waf/waf.lua;
            body_filter_by_lua_file /path/to/ngx-lua-waf/response.lua;
            proxy_pass http://backend;
        }
    }
}
```

> **注意**：`lua_shared_dict` 必须在 `http` 块中定义，且名称不可更改（`waf_cc`、`waf_ban`）。

### 2. 修改配置

编辑 `config.lua`，根据业务场景选择开关：

```lua
-- ============================================================
-- 一键场景配置（修改下方开关即可）
-- ============================================================
-- | 场景              | BlockDangerous | BlockAggressive | CCEnhanced |
-- |-------------------|----------------|-----------------|------------|
-- | A. 通用企业官网   | on             | off             | off        |
-- | B. SpringBoot/K8s | on             | off             | on         |
-- | C. Laravel/PHP    | on             | off             | on         |
-- | D. Node.js/前端   | on             | off             | on         |
-- | E. 高安全/内部系统| on             | on              | on         |
-- ============================================================

BlockDangerous="on"
BlockAggressive="off"
BlockReferer="on"
BlockMethod="on"

-- 增强 CC 防御开关（默认 off，向后兼容）
CCEnhanced="off"

-- 若开启 CCEnhanced，参考以下场景化配置：
-- CCGlobalRate = "2000/60"       -- 全站 60 秒 2000 次
-- CCStaticRate = "600/60"        -- 静态文件 60 秒 600 次
-- CCStaticNoRefererRate = "200/60" -- 无 Referer 静态请求更严格
-- CCDynamicRate = "120/60"       -- 动态请求 60 秒 120 次
```

### 3. 配置 IP 白名单（支持 CIDR）

```lua
ipWhitelist={
    "127.0.0.1",
    "10.0.0.0/8",        -- 内网段
    "172.16.0.0/12",     -- K8s 内网
    "192.168.0.0/16",    -- 公司内网
    "100.64.0.0/10",     -- 阿里云 SLB（按需）
}
```

> **重要**：若使用 CC 防护，务必将负载均衡和监控探针 IP 加入白名单，否则健康检查会被误杀。

### 4. 配置 XFF 信任代理（获取真实 IP）

```lua
TrustedProxies = {
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.1/32",
}
```

### 5. 重启 / 热更新

| 修改内容 | 生效方式 | 说明 |
|---------|---------|------|
| `wafconf/` 下的规则文件 | **无需任何操作** | 基于 `RuleCacheTTL`（默认 5 秒）自动刷新 |
| `config.lua` | `nginx -s reload` | 大部分配置 reload 即可 |
| `waf.lua` / `response.lua` | `nginx -s reload` | `access_by_lua` / `body_filter_by_lua` 阶段 reload 生效 |
| `init.lua` / `lib/*.lua` | **`nginx -s stop && nginx`** | 若 `nginx.conf` 中使用了 `init_by_lua_file`，reload **不会**重新执行 `init.lua` |

如需立即刷新规则缓存：
```bash
# 命令行工具（推荐，无需 HTTP 接口）
./waf-cli reload

# 或访问管理接口（仅限内网）
curl "http://localhost/waf-admin?action=reload"
```

---

## 配置详解

### 基础配置

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `RulePath` | string | `/u/nginx/ngx_lua_waf/wafconf/` | 规则文件存放目录 |
| `attacklog` | string | `on` | 是否记录攻击日志 |
| `logdir` | string | `/u/medsci/logs/nginx/` | 日志存放目录 |
| `UrlDeny` | string | `on` | 是否启用 URL 黑名单检测 |
| `Redirect` | string | `on` | 拦截后是否返回拦截页面 |
| `CookieMatch` | string | `on` | 是否启用 Cookie 检测 |
| `postMatch` | string | `on` | 是否启用 POST 检测 |
| `whiteModule` | string | `on` | 是否启用 URL 白名单 |
| `black_fileExt` | table | `{"php","jsp","aspx","py","sh"}` | 上传文件黑名单扩展名 |
| `ipWhitelist` | table | `{"127.0.0.1"}` | IP 白名单（支持 CIDR） |
| `ipBlocklist` | table | `{"1.0.0.1"}` | IP 黑名单（支持 CIDR） |
| `CCDeny` | string | `off` | 原版 CC 防护开关 |
| `CCrate` | string | `120/60` | 原版 CC 阈值：60 秒内 N 次请求 |
| `BlockDangerous` | string | `on` | 敏感路径/文件检测（core） |
| `BlockAggressive` | string | `off` | 激进规则（health/metrics/debug/txt） |
| `BlockReferer` | string | `on` | 恶意 Referer 检测 |
| `BlockMethod` | string | `on` | 禁止 TRACE/TRACK |
| `BlockHeader` | string | `on` | Header 层攻击检测 |
| `BlockResponse` | string | `on` | 响应敏感信息泄露检测 |
| `WafDebug` | string | `off` | WAF 调试日志开关：`on` 时所有 `WAF_` 前缀的跟踪日志写入 nginx error log |

### 增强功能配置

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `RuleCacheTTL` | number | `5` | 规则缓存刷新间隔（秒），0 表示每次请求都读磁盘 |
| `TrustedProxies` | table | 内网三段 | XFF 信任代理 CIDR 列表 |
| `RealIPStrategy` | string | `left` | XFF 取 IP 策略：`left` 最左 / `right` 最右 |
| `LogRateLimit` | number | `0` | 日志限流：同 IP 同规则 60 秒内最多记录 N 条（0 不限） |
| `CCEnhanced` | string | `off` | **增强 CC 总开关**（开启后覆盖旧版 `CCDeny`） |
| `CCGlobalRate` | string | `2000/60` | 全站全局限制（所有请求类型总计） |
| `CCStaticEnabled` | string | `on` | 静态文件 CC 是否启用 |
| `CCStaticRate` | string | `600/60` | 正常静态文件请求阈值 |
| `CCStaticNoRefererRate` | string | `200/60` | 无 Referer 静态请求阈值（更严格） |
| `CCStaticNoCookieRate` | string | `300/60` | 无 Cookie 静态请求阈值 |
| `CCDynamicRate` | string | `120/60` | 普通动态页面阈值 |
| `CCApiRate` | string | `300/60` | API 接口阈值 |
| `CCUploadRate` | string | `30/60` | 文件上传阈值 |
| `CCPostMultiplier` | number | `0.5` | POST 请求阈值收紧系数（0.5 = 减半） |
| `CCProgressive` | string | `on` | 渐进式惩罚开关 |
| `CCBanDuration1` | number | `60` | 第 1 次超限封禁秒数 |
| `CCBanDuration2` | number | `300` | 第 2 次超限封禁秒数 |
| `CCBanDuration3` | number | `3600` | 第 3 次及以上封禁秒数 |
| `CCChallengeEnabled` | string | `on` | Cookie 挑战验证开关 |
| `CCChallengeCookie` | string | `_waf_cc` | 挑战验证 Cookie 名称 |
| `CCChallengeTTL` | number | `300` | 挑战验证 Cookie 有效期（秒） |
| `ActionMode` | string | `block` | 全局默认动作：`block`（拦截）/ `log`（仅记录） |
| `CCAction` | string | `block` | CC 防御动作模式（可覆盖全局） |
| `IPBlockAction` | string | `block` | IP 黑名单动作模式 |
| `ArgsAction` | string | `block` | GET 参数检测动作模式 |
| `URLAction` | string | `block` | URL 黑名单动作模式 |
| `DangerousAction` | string | `block` | 敏感路径检测动作模式 |
| `HeaderAction` | string | `block` | Header 攻击检测动作模式 |
| `WafCmdDir` | string | `/tmp/waf-cmd` | 命令行工具管道目录 |

---

## 增强功能说明

### 1. 增强 CC 防御（CCEnhanced）

原版 CC 防御只有一个计数器（`IP + URI`），无法区分静态文件和动态请求，且白名单 URL 仍会被拦截。增强版提供：

**请求自动分类**：
- `static` — `.js` `.css` `.png` 等 + `/static/` `/assets/` 路径
- `api` — `/api/` `/graphql` 路径 + 非静态路径的 `.json`
- `upload` — `multipart/form-data`
- `dynamic` — 其他所有请求

**三级独立计数**：

| 级别 | Key | 说明 |
|------|-----|------|
| 全局 | `global:{IP}` | 该 IP 全站所有请求总计 |
| 静态 | `static:{IP}` | 该 IP 静态文件请求总计 |
| 动态 | `dynamic:{IP}:{URI}` | 该 IP 单个 URI 请求计数 |

**Bot 信号联动**：根据 UA / Referer / Cookie / Accept 等信号评分，高风险 Bot 的 CC 阈值自动降低 70%。

**渐进式惩罚**：

```
第 1 次超限 → 503 Service Unavailable
第 2 次超限 → 302 Set-Cookie 挑战（简单脚本无法自动通过）
第 3 次超限 → 封禁 IP 5 分钟
第 4 次+    → 封禁 IP 1 小时
```

**关键改进：检测链顺序调整**。`whiteurl()` 现在放在 `denycc()` 之前，白名单中的静态资源路径**不会再被 CC 拦截**。

### 2. 规则缓存（RuleCacheTTL）

原版每次 `require 'init'` 都会重新读取规则文件（实际上被 `require` 缓存，导致热更新不生效）。增强版：
- Worker 级缓存，默认每 5 秒检查一次文件变化
- 规则真正热更新，无需 `nginx -s reload`
- 可通过管理接口 `/waf-admin?action=reload` 强制立即刷新

### 3. XFF 真实 IP 解析

在 CDN / 负载均衡后，原版只能获取到代理 IP。增强版：
- 自动解析 `X-Forwarded-For`
- 支持配置信任代理 CIDR 列表
- 跳过信任代理，返回第一个非信任 IP

### 4. CIDR 网段支持

IP 黑白名单支持 `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16` 等 CIDR 格式，无需逐条配置内网 IP。

### 5. 多重解码链

防御 URL 双重编码、HTML Entity、Unicode、Hex 等绕过手段：

```
原始输入 → URL Decode → HTML Entity Decode → \xNN Decode → 最终检测
```

### 6. 按模块告警模式（ActionMode）

每个检测模块可独立配置为 `block`（拦截）或 `log`（仅记录日志，不阻止请求）。

**全局切换为仅告警模式：**
```lua
ActionMode = "log"
```

**仅让特定模块告警（其他正常拦截）：**
```lua
ActionMode = "block"
CCAction = "log"              -- CC 只告警不封禁
DangerousAction = "log"       -- 敏感路径只记录不拦截
```

告警模式下的行为：
- 攻击日志正常写入 `*_sec.log`
- 检测计数、Bot 评分正常执行
- 请求**不会被拦截**，继续向后端传递

### 7. 命令行管理工具（waf-cli）

`waf-cli` 通过文件管道与运行中的 WAF 通信，**无需开放任何 HTTP 管理接口**，适合安全管控严格的生产环境。

```bash
# 解除指定 IP 的 CC 封禁（同时清零其历史超限记录）
./waf-cli unban 1.2.3.4

# 查看当前被封禁的 IP 列表
./waf-cli banlist

# 强制刷新规则缓存
./waf-cli reload

# 查看某 IP 的 CC 统计
./waf-cli stats 1.2.3.4
```

**工作原理：**
1. `waf-cli` 将请求写入 `/tmp/waf-cmd/req-xxx.json`
2. WAF 在处理 HTTP 请求时（每秒最多检查一次）读取并执行
3. 结果写回 `/tmp/waf-cmd/res-xxx.json`
4. `waf-cli` 读取响应并输出

> ⚠️ 需要有 HTTP 请求经过 WAF 才能触发命令处理。如果当前无流量，命令会等待直到有请求进来。

---

## 场景化配置速查

### A. 通用企业官网 / 博客（默认）

```lua
BlockDangerous="on"
BlockAggressive="off"
CCEnhanced="off"          -- 静态资源少，暂不启用
```

### B. Spring Boot / K8s 微服务

```lua
BlockDangerous="on"
BlockAggressive="off"     -- 必须关闭，否则探针失效
CCEnhanced="on"
CCGlobalRate="2000/60"
CCDynamicRate="600/60"    -- API 较多，动态请求稍宽松
CCApiRate="1000/60"
```

### C. Laravel / ThinkPHP / WordPress

```lua
BlockDangerous="on"
BlockAggressive="off"
CCEnhanced="on"
CCGlobalRate="2000/60"
CCDynamicRate="300/60"
CCStaticRate="600/60"
```

### D. Node.js / React / Vue（前端资源多）

```lua
BlockDangerous="on"
BlockAggressive="off"
CCEnhanced="on"
CCStaticRate="1000/60"    -- 静态资源多，适当放宽
CCDynamicRate="300/60"
CCStaticNoRefererRate="300/60"
```

### E. 图片/视频站 / 下载站（带宽敏感）

```lua
BlockDangerous="on"
BlockAggressive="off"
CCEnhanced="on"
CCGlobalRate="1000/60"         -- 全站收紧
CCStaticRate="300/60"          -- 静态资源严格
CCStaticNoRefererRate="100/60" -- 无 Referer 极严格（防盗链刷量）
CCDynamicRate="60/60"
```

### F. 遭受大规模 CC 攻击时的紧急配置

```lua
CCEnhanced="on"
CCGlobalRate="500/60"
CCStaticRate="100/60"
CCStaticNoRefererRate="30/60"
CCDynamicRate="30/60"
CCProgressive="on"
CCBanDuration1=300     -- 首次即封禁 5 分钟
CCBanDuration2=1800    -- 二次封禁 30 分钟
CCBanDuration3=86400   -- 三次封禁 1 天
```

---

## 规则文件格式

### 普通规则文件（url / args / post / cookie / user-agent / referer / method）

每行一条 PCRE 正则，空行和 `#` 注释会被自动过滤：

```
# SQL 注入特征
select.+(from|limit)
(?:(union(.*?)select))

# XSS
<(iframe|script|body|img|layer|div|meta|style|base|object|input)
```

### 带标记的规则文件（dangerous）

支持技术栈分组标记，`read_tagged_rule()` 会自动解析：

```
# [core]
^/\.git(/.*)?$
^/\.env$

# [java]
^/actuator/(env|beans|heapdump|...)$
^/druid(/.*)?$

# [php]
^/_ignition(/.*)?$
^/wp-config\.php$

# [aggressive]
^/health$
^/metrics(/.*)?$
```

- `# [core]` / `# [java]` / `# [nodejs]` / `# [php]` / `# [aggressive]` 为保留标记
- 标记后的所有规则归属该分组，直到下一个标记出现

---

## 日志格式

日志文件：`{logdir}/{server_name}_{date}_sec.log`

每行格式：

```
IP [时间] "方法 域名URI" "数据" "UA" "命中标记"
```

### 示例

```
192.168.1.1 [2025-06-10T14:30:00+08:00] "GET example.com/actuator/env" "-" "Mozilla/5.0..." "[DANGEROUS][core][404] hit=[/actuator/env] rule=^/actuator/(env|beans|heapdump|...)$"
192.168.1.2 [2025-06-10T14:31:00+08:00] "GET example.com/index.php?id=1' or '1'='1" "-" "sqlmap/1.0" "[ARGS][403] hit=[SELECT * FROM users] rule=select.+(from|limit)"
192.168.1.3 [2025-06-10T14:32:00+08:00] "POST example.com/upload" "-" "Mozilla/5.0..." "[FILEEXT][403] hit=[php] rule=php"
```

### 调试日志（WafDebug）

当 `WafDebug = "on"` 时，nginx error log 会输出以下跟踪信息：

| 日志标识 | 说明 |
|---------|------|
| `WAF_ENTRY` | 请求进入 WAF，显示 IP、Method、URI、UA、attacklog 状态、logpath 路径 |
| `WAF_PASS` | 某检测模块通过（如 `blockip`、`headers`、`denycc` 等） |
| `WAF_BLOCK` | 某检测模块拦截命中 |
| `WAF_WHITEIP` / `WAF_WHITEURL` | 请求被白名单放行 |
| `WAF_ALL_PASS` | 所有检测通过，请求放行到后端 |
| `WAF_RESPONSE` | 进入响应过滤阶段 |
| `WAF_LOG_OK` / `WAF_LOG_FAIL` | sec.log 写入成功/失败，含完整文件路径和日志内容 |
| `WAF_LOG_SKIP` | 日志被跳过（通常因为 `attacklog=off` 或限流） |
| `WAF_RULES_LOADED` | 规则加载汇总，显示各模块规则条数 |

**生产环境建议**：保持 `WafDebug = "off"`，避免 error log 被大量 WAF 跟踪日志撑满。

---

### 命中标记说明

| 标记 | 含义 | 状态码 | `hit` 示例 |
|------|------|--------|-----------|
| `[ARGS]` | GET 参数命中攻击规则 | 403 | `hit=[SELECT * FROM users]` |
| `[URL]` | URI 命中黑名单 | 403 | `hit=[phpmyadmin]` |
| `[POST]` | POST 参数命中攻击规则 | 403 | `hit=[UNION SELECT * FROM users]` |
| `[COOKIE]` | Cookie 命中攻击规则 | 403 | `hit=[<script>alert(1)</script>]` |
| `[UA]` | User-Agent 命中黑名单 | 403 | `hit=[sqlmap]` |
| `[FILEEXT]` | 上传文件扩展名命中黑名单 | 403 | `hit=[php]` |
| `[DANGEROUS][core]` | 敏感路径/文件（核心规则） | 404 | `hit=[/.env]` |
| `[DANGEROUS][java]` | Java 技术栈敏感端点 | 404 | `hit=[/druid/index.html]` |
| `[DANGEROUS][php]` | PHP 技术栈敏感端点 | 404 | `hit=[/_ignition/execute-solution]` |
| `[DANGEROUS][nodejs]` | Node.js 技术栈敏感端点 | 404 | `hit=[/.env.local]` |
| `[DANGEROUS][aggressive]` | 激进规则（health/metrics/debug 等） | 404 | `hit=[/health]` |
| `[REFERER]` | 恶意 Referer | 403 | `hit=[semalt.com]` |
| `[METHOD]` | 禁止的 HTTP 方法（TRACE/TRACK） | 403 | `hit=[TRACE]` |
| `[TRAVERSAL]` | 路径穿越/空字节 | 400 | `hit=[../../..]` |
| `[HEADER]` | Header 层攻击（走私/伪造/注入） | 403 | `hit=[X-Forwarded-Host: evil.com]` |
| `[RESPONSE]` | 响应敏感信息泄露（堆栈/路径/密钥） | 500 | `hit=[java.lang.NullPointerException]` |
| `[IPBLOCK]` | IP 黑名单命中 | 403 | `hit=[1.2.3.4]` |
| `[CC-BAN]` | CC 超限被封禁 | 503 | `ip=x.x.x.x level=3 duration=300s` |

---

## 误伤风险控制

### 核心规则（core）— 默认开启，误伤低

覆盖范围：隐藏文件、Git/SVN/IDE 目录、Actuator 敏感端点（**不含** `/actuator/health`）、Swagger/OpenAPI、phpinfo、nginx_status、密钥/凭证/配置文件/数据库/压缩包扩展名、SSH 密钥、Docker/K8s 敏感文件、core dump、Java/Node.js/PHP 技术栈特有敏感端点（Druid、_ignition、Telescope 等）。

### 激进规则（aggressive）— 默认关闭，误伤高

以下场景**必须关闭** `BlockAggressive`：

| 规则 | 误伤场景 |
|------|---------|
| `^/health$` / `^/metrics$` | K8s livenessProbe、Prometheus 监控被阻断 |
| `^/.*debug.*/.*$` | 正常业务路径如 `/api/debug-mode` 被拦截 |
| `^/(debug\|test\|tests\|dev\|staging\|sandbox)(/.*)?$` | 技术站点的 `/test` 在线测试页被拦截 |
| `/(?!robots).*\.txt$` | 合法的 `/license.txt`、`/changelog.txt` 被拦截 |
| `\.(py\|sh\|java\|map)$` | Python/Shell 教程站点、代码分享平台、SourceMap 调试 |

---

## 常见问题

### Q1: 上线后部分正常请求被拦截，如何排查？

```bash
# 查看今天被拦截的请求
tail -f /u/medsci/logs/nginx/example.com_$(date +%Y-%m-%d)_sec.log

# 按命中类型统计
grep -oP '\[\w+\]\[\d+\]' /u/medsci/logs/nginx/*_sec.log | sort | uniq -c

# 查看实际命中的攻击关键词
grep -oP 'hit=\[\K[^\]]+' /u/medsci/logs/nginx/*_sec.log | sort | uniq -c | sort -rn | head -n 20

# 查看是否命中激进规则
grep '\[DANGEROUS\]\[aggressive\]' /u/medsci/logs/nginx/*_sec.log

# 查看 SQL 注入具体命中了什么
grep '\[ARGS\]\|\[POST\]' /u/medsci/logs/nginx/*_sec.log | grep -oP 'hit=\[\K[^\]]+'

# 查看响应泄露（错误堆栈、密钥暴露）
grep '\[RESPONSE\]' /u/medsci/logs/nginx/*_sec.log

# 查看 CC 封禁记录
grep '\[CC-BAN\]' /u/medsci/logs/nginx/cc_ban.log

# 查看 Header 攻击（请求走私、代理伪造）
grep '\[HEADER\]' /u/medsci/logs/nginx/*_sec.log
```

若发现 `[DANGEROUS][aggressive]` 误伤，将 `BlockAggressive` 设为 `off`。

### Q2: K8s 的 `/healthz` 被 404 了怎么办？

```lua
-- config.lua
BlockAggressive="off"   -- 关闭激进规则组
```

或单独将探针 IP 加入白名单：

```lua
ipWhitelist={"127.0.0.1","10.0.0.0/8","172.16.0.0/12"}
```

### Q3: 规则文件修改后需要 reload 吗？

**不需要**。`wafconf/` 下的规则文件在 Worker 缓存 TTL（默认 5 秒）后自动刷新。如需立即生效：

```bash
# 方式一：命令行工具（推荐，无需 HTTP 接口）
./waf-cli reload

# 方式二：管理接口（仅限内网）
curl "http://localhost/waf-admin?action=reload"
```

### Q4: 如何添加自定义规则？

直接在对应规则文件中追加 PCRE 正则即可：

```bash
# 拦截自定义后台路径
echo '^/myadmin(/.*)?$' >> wafconf/dangerous
```

如需按技术栈标记，写在 `dangerous` 文件中并加上 `# [custom]` 标记头。

### Q5: 日志量太大怎么办？

```lua
-- 开启日志限流，同 IP 同规则 60 秒内最多记录 10 条
LogRateLimit = 10
```

其他措施：
- 关闭不必要的模块：`CookieMatch="off"`、`BlockReferer="off"`
- 使用 `logrotate` 按天切割日志
- 将日志接入 ELK / Loki 做集中存储和检索

### Q5.1: error log 中有 WAF 日志，但 sec.log 文件没有记录？

按以下顺序排查：

1. **检查 `attacklog` 是否生效**
   ```bash
   tail -f /u/medsci/logs/nginx/error.log | grep WAF_ENTRY
   ```
   如果看到 `attacklog=nil`，说明 `config.lua` 中的 `attacklog = "on"` 没有生效。检查服务器上实际运行的 `config.lua` 内容：
   ```bash
   cat /path/to/ngx-lua-waf/config.lua | grep attacklog
   ```

2. **检查 sec.log 写入状态**
   开启调试模式后，error log 会显示每次写入结果：
   ```lua
   WafDebug = "on"   -- 临时开启排查
   ```
   ```bash
   nginx -s reload
   tail -f error.log | grep 'WAF_LOG_OK\|WAF_LOG_FAIL\|WAF_LOG_SKIP'
   ```
   - `WAF_LOG_OK` → 写入成功，检查 `file=` 后的路径是否正确
   - `WAF_LOG_FAIL` → 写入失败，根据 `err=` 修复权限/目录问题
   - `WAF_LOG_SKIP: attacklog=off` → `attacklog` 未生效，见第 1 步

3. **检查日志路径权限**
   ```bash
   ls -ld /u/medsci/logs/nginx/
   touch /u/medsci/logs/nginx/test_write && rm /u/medsci/logs/nginx/test_write
   ```

4. **检查 nginx 配置中是否使用了 `init_by_lua_file`**
   如果 `init.lua` 是在 `init_by_lua_file` 中加载的，修改 `init.lua` 后 **`nginx -s reload` 不会生效**，必须执行：
   ```bash
   nginx -s stop && nginx
   ```

### Q6: WAF 调试日志开关怎么使用？

```lua
-- config.lua
WafDebug = "on"   -- 排查问题时临时开启
WafDebug = "off"  -- 生产环境默认关闭
```

开启后，nginx error log 会输出完整的请求跟踪：
```
WAF_ENTRY: ip=1.2.3.4 method=GET uri=/swagger.json attacklog=true logpath=...
WAF_PASS: module=blockip ip=1.2.3.4 uri=/swagger.json
WAF_BLOCK: module=dangerous ip=1.2.3.4 uri=/swagger.json
WAF_LOG_OK: file=..._sec.log line=...
```

**注意**：`init.lua` 在 `init_by_lua_file` 阶段执行时，`WafDebug` 的读取也在该阶段。如果修改后不生效，需要 `nginx restart`。

### Q7: 如何确认增强 CC 已生效？

开启后，被 CC 拦截的请求会返回以下响应头：

```
X-WAF-CC-Status: static-limit    # 或 global-limit / dynamic-limit
X-WAF-CC-Count: 201              # 当前计数
X-WAF-CC-Limit: 200              # 阈值
```

### Q8: 如何查看某个 IP 的 CC 统计？

```bash
# 方式一：命令行工具（推荐）
./waf-cli stats 1.2.3.4

# 方式二：管理接口（仅限内网）
curl "http://localhost/waf-admin?action=stats&ip=1.2.3.4"
```

---

### Q9: 如何解除被封禁的 IP？

CC 封禁（由 `waf_ban` 共享字典管理）到期会自动释放。如需手动提前解封：

```bash
# 解除指定 IP 的 CC 封禁
./waf-cli unban 1.2.3.4

# 查看当前被封禁的 IP 列表
./waf-cli banlist
```

如果是 `ipBlocklist` 配置导致的永久拦截，需从 `config.lua` 中移除该 IP 并 `nginx -s reload`。

---

### Q10: 如何只告警不拦截？

**全局切换为仅告警模式**（所有模块只记录日志，不阻止请求）：

```lua
ActionMode = "log"
```

**仅让特定模块告警**（其他模块正常拦截）：

```lua
ActionMode = "block"
CCAction = "log"              -- CC 只告警不封禁
ArgsAction = "log"            -- GET 参数攻击只记录
DangerousAction = "log"       -- 敏感路径只记录
```

---

### Q11: CC 惩罚时间如何设置？

编辑 `config.lua`：

```lua
CCBanDuration1 = 60     -- 第1次超限封禁 60 秒
CCBanDuration2 = 300    -- 第2次封禁 5 分钟
CCBanDuration3 = 3600   -- 第3次封禁 1 小时
```

修改后 `nginx -s reload` 生效，**只影响新触发的封禁**，已封禁的 IP 保持原时长不变。如需立即解封已有 IP，使用 `./waf-cli unban <ip>`。

---

## 技术栈覆盖清单

| 技术栈 | 覆盖端点/文件 |
|--------|--------------|
| **Spring Boot** | `/actuator/env|beans|heapdump|...`、`/swagger-ui`、`/druid`、`/h2-console`、`/jolokia` |
| **Java 通用** | `*.jar`、`*.war`、`*.class`、`*.java`（aggressive） |
| **Node.js** | `/node_modules`、`package.json`、`npm-debug`、`__webpack_dev_server__`、`*.map`（aggressive） |
| **Laravel** | `/_debugbar`、`/_ignition`、`/telescope`、`/horizon`、`/.env` |
| **ThinkPHP** | `/thinkphp` |
| **WordPress** | `/wp-config.php`、`/wp-admin/install.php`、`/wp-content/debug.log`、`/wp-login` |
| **PHP 通用** | `phpinfo.php`、`*.php~`、`composer.lock`、`phpunit.xml` |
| **Python** | `*.py`、`*.pyc`、`manage.py`、`wsgi.py`、`celery.py`（aggressive） |
| **DevOps** | `Dockerfile`、`docker-compose.yml`、`Jenkinsfile`、`*.tf`、`*.tfvars`、`Chart.yml` |
| **数据库** | `*.sql`、`*.sqlite`、`*.db`、`*.mdb`、`*.dump` |
| **密钥/凭证** | `id_rsa`、`authorized_keys`、`*.pem`、`*.p12`、`*.pfx`、`credentials.json` |

---

## 许可证

MIT License
