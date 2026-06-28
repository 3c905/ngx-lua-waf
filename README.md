# ngx-lua-waf

基于 OpenResty / Nginx + Lua 的轻量级 Web 应用防火墙。定位是**在业务流量入口提供低开销、可观测、低误伤的基础防御**，适合单机或小集群场景。

核心设计原则：

1. **分层规则**：`wafconf/dangerous` 分为 `[core]`（默认开启）与 `[aggressive]`（默认关闭）。`user-agent` 与 `method` 保持较强拦截策略，其他模块优先低误伤。
2. **规则准确**：每条规则尽量带词边界，拦截“语法结构”而非“常见单词”。
3. **CVE 覆盖**：内置常见高危 CVE 路径与利用特征，持续补充。
4. **可观测**：所有命中都会写入 `*_sec.log`，支持按模块独立配置 `block` / `log`。

---

## 目录结构

```
ngx-lua-waf/
├── config.lua              # 主配置文件
├── init.lua                # 核心函数库（规则读取、检测、日志）
├── waf.lua                 # WAF 入口（access 阶段）
├── response.lua            # 响应过滤入口（body_filter 阶段）
├── lib/
│   ├── cache.lua           # Worker 级规则缓存 + 正则预编译
│   ├── utils.lua           # XFF/CIDR/请求分类/Bot 检测/解码链
│   └── cc_enhanced.lua     # 增强版 CC 防御
├── wafconf/                # 规则文件
│   ├── url                 # URI 路径黑名单
│   ├── args                # GET 参数攻击特征
│   ├── post                # POST 参数攻击特征
│   ├── cookie              # Cookie 攻击特征
│   ├── user-agent          # 恶意 UA
│   ├── whiteurl            # URL 白名单
│   ├── header              # Header 层攻击检测
│   ├── response            # 响应敏感信息泄露
│   ├── dangerous           # 敏感路径/文件/CVE（含 core/aggressive 分组）
│   ├── referer             # 恶意 Referer
│   └── method              # HTTP 方法限制
├── tests/                  # 单元测试与规则校验
│   ├── test_cache.lua
│   ├── test_utils.lua
│   ├── validate_rules.py
│   ├── check_lua_syntax.py
│   └── run_tests.sh
├── waf-cli                 # 命令行管理工具
├── nginx-example.conf      # Nginx 配置示例
└── install.sh              # 安装脚本（参考）
```

---

## 功能特性

| 模块 | 说明 |
|------|------|
| **IP 黑白名单** | 支持精确 IP 和 CIDR 网段 |
| **CC 攻击防护** | 原版计数器 + 增强版分级限速（全局/静态/动态/API/上传） |
| **URL 黑名单** | 敏感路径、已知 CVE、WebShell 文件名 |
| **参数检查** | GET/POST/Cookie 的 SQLi、NoSQL、XSS、RCE、SSRF、SSTI、反序列化 |
| **文件上传检查** | 黑名单扩展名 + 双扩展名 + 图片马特征 |
| **敏感路径屏蔽** | Git/IDE/Actuator/Swagger/密钥/数据库/中间件后台等 |
| **Header 攻击检测** | 请求走私、CRLF、Header 注入载荷 |
| **响应泄露检测** | 错误堆栈、内部路径、数据库连接串、密钥 Token |
| **Bot 信号检测** | UA/Referer/Cookie/Accept 多维评分 |
| **规则缓存** | Worker 级缓存 + TTL + 正则预编译 |
| **按模块告警模式** | 每个检测模块可独立 `block` 或 `log` |
| **命令行管理** | `waf-cli` 管理封禁/解封/规则刷新 |

---

## 快速开始

### 1. Nginx 配置

在 `nginx.conf` 的 `http` 块中加入：

```nginx
http {
    # WAF 共享内存字典
    lua_shared_dict limit      50m;
    lua_shared_dict waf_cc     100m;
    lua_shared_dict waf_ban    50m;

    # Lua 包路径
    lua_package_path "/path/to/ngx-lua-waf/?.lua;/path/to/ngx-lua-waf/lib/?.lua;;";
    lua_code_cache on;

    # 初始化 WAF
    init_by_lua_file /path/to/ngx-lua-waf/init.lua;

    server {
        listen 80;
        server_name example.com;

        access_by_lua_file /path/to/ngx-lua-waf/waf.lua;

        location / {
            body_filter_by_lua_file /path/to/ngx-lua-waf/response.lua;
            proxy_pass http://backend;
        }
    }
}
```

> 完整示例见 `nginx-example.conf`。

### 2. 修改配置

编辑 `config.lua`：

```lua
# 默认推荐（低误伤）
BlockDangerous="on"
BlockAggressive="off"
BlockReferer="on"
BlockMethod="on"
BlockHeader="on"
BlockResponse="on"
ResponseAction="log"   # 响应泄露先仅告警
```

### 3. 配置 IP 白名单

```lua
ipWhitelist={
    "127.0.0.1",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
}
```

### 4. 重启 / 热更新

| 修改内容 | 生效方式 |
|---------|---------|
| `wafconf/` 规则文件 | 自动（`RuleCacheTTL` 默认 5 秒） |
| `config.lua` | `nginx -s reload` |
| `init.lua` / `lib/*.lua` | `nginx -s stop && nginx` |

手动刷新规则：

```bash
./waf-cli reload
```

---

## 规则说明

### 规则文件格式

普通规则文件每行一条 PCRE 正则，空行和 `#` 注释会被过滤。

```
# SQL 注入示例
\bunion\s+select\b
```

`dangerous` 支持 `[core]` / `[java]` / `[nodejs]` / `[php]` / `[aggressive]` 分组。

### 核心规则（core）

默认开启，覆盖：

- 路径穿越与空字节
- SQL 注入、NoSQL 注入
- 命令注入、PHP 代码执行/LFI
- XSS、JNDI/Log4Shell、Spring4Shell
- SSRF 内网 IP / 元数据地址
- JWT `alg:none` / `jwk` / `x5c`
- Java/.NET/PHP 反序列化特征
- 敏感文件泄露（`.env`、SSH 密钥、core dump 等）
- 已知 CVE 路径（PHPUnit、WebLogic、JBoss、Solr、UEditor、Jenkins、GitLab、Confluence、ES/Kibana、Grafana、Airflow、Spark、Harbor、ArgoCD 等）
- Spring Boot / Spring Cloud 系列 CVE（Spring4Shell、Spring Cloud Gateway、Spring Cloud Function、Spring Data REST 等）
- PHP 框架 CVE（Laravel Ignition、ThinkPHP、WordPress 插件、Drupal、Joomla、Magento、Typecho 等）
- Node.js 调试接口与常见框架后台（Node-RED、Strapi、Ghost、Express status-monitor 等）
- Python 框架敏感端点（Django admin、Flask debug console、FastAPI docs、Celery/Flower 等）
- Go 框架（pprof、Gin/Echo/Beego admin、Swagger、go.mod）
- .NET / ASP.NET（trace.axd、elmah.axd、.svc、.asmx、Identity）
- Ruby / Rails（ActiveAdmin、Sidekiq、Rails console/routes）
- 云原生（Kubernetes API、etcd、Docker Registry、Harbor、Istio、Vault、Consul、Nomad、Rancher、Portainer、AWX）
- 数据库（MySQL、PostgreSQL、Redis、MongoDB、ES/Kibana、ClickHouse、InfluxDB、TiDB、CockroachDB、Neo4j）
- 中间件（Kafka、RocketMQ、Pulsar、Nacos、Apollo、ZooKeeper、ActiveMQ、EMQ X、NATS、Traefik、Envoy、HAProxy、Memcached、MinIO）
- TRACE/TRACK 方法、WebDAV 方法、扫描器非标准方法前缀

### 激进规则（aggressive）

默认关闭，高误伤：

- 通用压缩包/源码/日志扩展名
- `health` / `metrics` / `version` / `v1`
- 所有 Actuator（含 health）
- `X-Forwarded-*` 头按头名封禁
- 通用 `test` / `debug` / `backup` 目录
- 部分命令行客户端/开发工具 UA

开启方式：

```lua
BlockAggressive="on"
```

---

## 配置项速查

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `RulePath` | `/u/nginx/ngx_lua_waf/wafconf/` | 规则目录 |
| `attacklog` | `on` | 是否记录攻击日志 |
| `logdir` | `/u/medsci/logs/nginx/` | 日志目录 |
| `RuleCacheTTL` | `5` | 规则缓存刷新秒数 |
| `LogRateLimit` | `50` | 同 IP 同规则 60 秒日志上限 |
| `WafDebug` | `off` | 调试日志开关 |
| `ActionMode` | `block` | 全局默认动作 |
| `CCEnhanced` | `off` | 增强 CC 总开关 |
| `BlockDangerous` | `on` | 敏感路径 core 规则 |
| `BlockAggressive` | `off` | 敏感路径 aggressive 规则 |
| `ResponseAction` | `log` | 响应泄露默认仅告警 |

各模块可独立覆盖：

```lua
IPBlockAction = "block"
CCAction = "block"
ArgsAction = "block"
PostAction = "block"
CookieAction = "block"
URLAction = "block"
DangerousAction = "block"
HeaderAction = "block"
ResponseAction = "log"   # 建议先 log
```

---

## 日志格式

文件：`{logdir}/{server_name}_{date}_sec.log`

```
IP [时间] "方法 域名URI" "数据" "UA" "命中标记"
```

示例：

```
192.168.1.1 [2025-06-10T14:30:00+08:00] "GET example.com/actuator/env" "-" "Mozilla/5.0..." "[DANGEROUS][core][404] hit=[/actuator/env]"
```

---

## 命令行工具

```bash
./waf-cli unban 1.2.3.4     # 解除 CC 封禁
./waf-cli banlist           # 查看封禁列表
./waf-cli reload            # 强制刷新规则缓存
./waf-cli stats 1.2.3.4     # 查看 IP 统计
```

---

## 测试

```bash
# 运行全部测试（需要 OpenResty 的 resty 命令）
./tests/run_tests.sh

# 单独校验规则正则语法
python3 tests/validate_rules.py

# 检查 Lua 语法
python3 tests/check_lua_syntax.py
```

---

## 常见排查

### 上线后部分正常请求被拦截

```bash
# 查看实时拦截日志
tail -f /path/to/logs/*_sec.log

# 按命中类型统计
grep -oP '\[\w+\]\[\d+\]' *_sec.log | sort | uniq -c

# 查看是否命中激进规则
grep '\[DANGEROUS\]\[aggressive\]' *_sec.log

# 查看具体命中关键词
grep -oP 'hit=\[\K[^\]]+' *_sec.log | sort | uniq -c | sort -rn | head -20
```

若发现激进规则误伤，将 `BlockAggressive` 设为 `off`。

### K8s /healthz 被拦截

```lua
BlockAggressive="off"
```

或把探针 IP 加入白名单。

### 响应泄露把正常错误页替换成 500

```lua
ResponseAction="log"
```

---

## 能力边界

- **单机 WAF**：依赖 Nginx worker 内存和共享字典，不适合大规模分布式 CC。
- **正则匹配**：存在被高级编码/分片绕过可能，需结合业务白名单使用。
- **响应检测**：`body_filter` 阶段可能分片，跨 chunk 的泄露可能漏检。
- **不是银弹**：不能替代代码安全、WAF 审计、SDL 流程。

---

## 许可证

MIT License
