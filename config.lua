RulePath = "/u/nginx/ngx_lua_waf/wafconf/"
attacklog = "on"
logdir = "/u/medsci/logs/nginx/"

-- WAF 调试日志开关：on 时所有 WAF_ 前缀的调试日志会写入 nginx error log
WafDebug = "off"

-- ============================================================
-- 一键场景配置指南（修改下方 5 个开关即可）
-- ============================================================
-- | 场景              | BlockDangerous | BlockAggressive | CCDeny  | 说明                         |
-- |-------------------|----------------|-----------------|---------|------------------------------|
-- | A. 通用企业官网   | on             | off             | off     | 默认推荐，平衡安全与业务     |
-- | B. SpringBoot/K8s | on             | off             | on      | 必须关闭 aggressive(health)  |
-- | C. Laravel/PHP    | on             | off             | on      | 核心规则已覆盖 PHP 敏感端点  |
-- | D. Node.js/前端   | on             | off             | on      | 同上，避免误伤 .map/.txt     |
-- | E. 高安全/内部系统| on             | on              | on      | 最大化拦截，接受一定误伤     |
-- ============================================================

UrlDeny="on"
Redirect="on"
CookieMatch="on"
postMatch="on"
whiteModule="on"

-- 上传文件黑名单扩展名
-- PHP 站点若允许用户上传 PHP 文件（如 CMS），请从列表中移除 "php"
black_fileExt={"php","jsp","aspx","py","sh"}

-- IP 白名单：负载均衡、CDN 回源、公司出口、监控探针等
-- 支持精确 IP 和 CIDR 网段，如 "10.0.0.0/8"
ipWhitelist={"127.0.0.1"}

-- IP 黑名单：支持精确 IP 和 CIDR 网段
ipBlocklist={"1.0.0.1","45.205.1.223","58.212.237.191","65.49.1.222","80.94.95.211","111.68.9.190","112.121.183.238","151.243.11.245","152.32.187.236","162.216.150.244","162.217.100.36","162.217.100.201","166.88.26.4","166.88.26.186","185.12.59.118","185.213.175.171","185.242.3.191","198.235.24.112","216.118.252.206","71.6.158.166","18.218.118.203","20.64.105.32","20.121.46.26","20.221.71.226","23.94.61.231","35.195.138.45","43.130.110.130","43.135.142.7","43.166.129.247","43.167.202.81","45.63.4.69","45.148.10.200","45.198.224.5","45.198.224.245","46.151.178.13","47.251.75.100","62.210.142.167","64.224.17.57","68.183.81.32","77.83.39.94","88.80.17.243","94.154.43.87","109.105.210.103","142.93.249.171","151.242.30.224","167.99.58.123","170.106.113.235","176.120.22.6","179.61.182.111","182.16.91.238"}

-- CC 防护：格式 "请求数/时间(秒)"
-- 场景 A: off           | 场景 B/C/D: "600/60"  | 场景 E: "120/60"
-- 日志中出现大量扫描器高频探测，建议开启
CCDeny="on"
CCrate="120/60"

-- 【block-dangerous.conf 合并规则】
-- core   = 低误伤：Git/密钥/凭证/配置文件/技术栈敏感端点（建议所有场景开启）
-- aggressive = 高误伤：health/metrics/debug/test/txt/py/sh/java/map（按需开启）
BlockDangerous="on"
BlockAggressive="off"

-- 恶意 Referer（SEO 垃圾流量）
BlockReferer="on"

-- 禁止 TRACE / TRACK 方法
BlockMethod="on"

-- Header 层攻击检测（请求走私、代理伪造、Header 注入）
BlockHeader="on"

-- 响应阶段敏感信息泄露检测（错误堆栈、内部路径、密钥泄露）
-- 注意：响应规则容易命中正常错误页，建议先以 log 模式运行观察
BlockResponse="on"
ResponseAction="log"

-- ============================================================
-- 【新增】增强功能配置
-- ============================================================

-- 规则缓存 TTL（秒），每 N 秒刷新一次规则文件
-- 设置为 0 则每次请求都重新读取（不推荐高并发场景）
RuleCacheTTL = 5

-- X-Forwarded-For 信任代理列表（CIDR 格式）
-- 配置前置负载均衡、CDN、WAF 的 IP 段
TrustedProxies = {
    -- 内网段
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.1/32",
    -- 阿里云 SLB（按需添加）
    -- "100.64.0.0/10",
    -- Cloudflare（按需添加）
    -- "173.245.48.0/20",
    -- "103.21.244.0/22",
}

-- 获取真实 IP 策略："left" 取 XFF 最左（默认），"right" 取最右
-- 最左适用于标准代理链；最右适用于某些 CDN 配置
RealIPStrategy = "left"

-- ============================================================
-- 【新增】增强 CC 防御配置
-- ============================================================

-- 启用增强 CC 防御（覆盖旧版 denycc）
CCEnhanced = "off"

-- 全站全局限制（所有请求类型总计）
CCGlobalRate = "2000/60"

-- 静态文件 CC 配置
CCStaticEnabled = "on"
CCStaticRate = "600/60"             -- 正常静态文件请求
CCStaticNoRefererRate = "200/60"    -- 无 Referer 的静态请求（更严格）
CCStaticNoCookieRate = "300/60"     -- 无 Cookie 的静态请求

-- 动态请求 CC 配置
CCDynamicRate = "120/60"            -- 普通动态页面
CCApiRate = "300/60"                -- API 接口
CCUploadRate = "30/60"              -- 文件上传

-- POST 请求收紧系数（0.5 表示阈值减半）
CCPostMultiplier = 0.5

-- 渐进式惩罚开关
CCProgressive = "on"
CCBanDuration1 = 60     -- 第1次超限封禁 60 秒
CCBanDuration2 = 300    -- 第2次封禁 5 分钟
CCBanDuration3 = 3600   -- 第3次封禁 1 小时

-- Cookie 挑战验证（防简单脚本）
CCChallengeEnabled = "on"
CCChallengeCookie = "_waf_cc"
CCChallengeTTL = 300

-- 日志限流：同一 IP 同一规则 60 秒内最多记录 N 条日志（0 表示不限流）
-- 建议高并发场景设为 10-50，防止日志磁盘被打满
LogRateLimit = 50

-- ============================================================
-- 【新增】各模块动作模式配置
-- ============================================================
-- 全局默认模式: "block" = 拦截并记录日志, "log" = 仅记录日志不拦截
ActionMode = "block"

-- 各模块可独立覆盖（未配置则继承全局 ActionMode）
-- 值: "block" 或 "log"
IPBlockAction = "block"      -- IP 黑名单
CCAction = "block"           -- CC 防御（含增强版）
MethodAction = "block"       -- HTTP 方法限制（TRACE/TRACK）
TraversalAction = "block"    -- 路径穿越/空字节
HeaderAction = "block"       -- Header 攻击检测
RefererAction = "block"      -- 恶意 Referer
UAAction = "block"           -- User-Agent 黑名单
DangerousAction = "block"    -- 敏感路径/文件
URLAction = "block"          -- URL 黑名单
ArgsAction = "block"         -- GET 参数攻击
CookieAction = "block"       -- Cookie 攻击
PostAction = "block"         -- POST 参数攻击
FileExtAction = "block"      -- 上传文件扩展名
ResponseAction = "log"       -- 响应敏感信息泄露：建议先仅告警
BodyLimitAction = "block"    -- 请求体大小限制（防 DoS）
ScannerAction = "block"      -- 扫描器特征头（Acunetix/X-Scan）

-- ============================================================
-- 【新增】命令行管理工具管道目录
-- ============================================================
-- waf-cli 命令行工具通过文件管道与 WAF 通信
-- 无需开放 HTTP 管理接口，适合生产环境安全管控
-- 默认自动使用 WAF 安装目录下的 waf-cmd 子目录
-- 如需自定义（例如避免 tmpfs 或权限问题），改成绝对路径即可
local waf_dir = string.match(debug.getinfo(1, "S").source:sub(2), "(.*)/")
WafCmdDir = waf_dir .. "/waf-cmd"

-- ============================================================
-- 拦截页面 HTML
-- ============================================================

html=[[
<html xmlns="http://www.w3.org/1999/xhtml"><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>网站防火墙</title>
<style>
p {
	line-height:20px;
}
ul{ list-style-type:none;}
li{ list-style-type:none;}
</style>
</head>

<body style=" padding:0; margin:0; font:14px/1.5 Microsoft Yahei, 宋体,sans-serif; color:#555;">

 <div style="margin: 0 auto; width:1000px; padding-top:70px; overflow:hidden;">
  
  
  <div style="width:600px; float:left;">
    <div style=" height:40px; line-height:40px; color:#fff; font-size:16px; overflow:hidden; background:#6bb3f6; padding-left:20px;">网站防火墙 </div>
    <div style="border:1px dashed #cdcece; border-top:none; font-size:14px; background:#fff; color:#555; line-height:24px; height:220px; padding:20px 20px 0 20px; overflow-y:auto;background:#f3f7f9;">
      <p style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><span style=" font-weight:600; color:#fc4f03;">您的请求带有不合法参数，已被网站管理员设置拦截！</span></p>
<p style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">可能原因：您提交的内容包含危险的攻击请求</p>
<p style=" margin-top:12px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:1; text-indent:0px;">如何解决：</p>
<ul style="margin-top: 0px; margin-bottom: 0px; margin-left: 0px; margin-right: 0px; -qt-list-indent: 1;"><li style=" margin-top:12px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">1）检查提交内容；</li>
<li style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">2）如网站托管，请联系空间提供商；</li>
<li style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">3）普通网站访客，请联系网站管理员；</li></ul>
    </div>
  </div>
</div>
</body></html>
]]
