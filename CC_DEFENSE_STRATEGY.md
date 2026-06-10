# CC 攻击防御策略建议（静态文件专项）

## 一、为什么静态文件需要专门的 CC 防御？

### 1.1 静态文件 CC 攻击的独特性

| 攻击类型 | 目标 | 影响 |
|----------|------|------|
| **带宽耗尽型** | 大文件（视频、图片、JS/CSS） | CDN 回源带宽暴涨，源站带宽被占满 |
| **缓存击穿型** | 带随机参数的静态资源 `style.css?v=随机数` | 绕过 CDN 缓存，全部回源 |
| **盗链刷量型** | 图片/媒体资源 | 第三方站点嵌入你的资源，消耗你的流量 |
| **爬虫过载型** | 全站静态资源遍历 | 蜘蛛爬虫无限深度抓取 |
| **DDoS 反射型** | 配合 HTTP Range 请求 | 小请求引发大响应，放大攻击效果 |

### 1.2 静态文件 vs 动态请求的防御差异

| 维度 | 动态请求 | 静态文件 |
|------|----------|----------|
| **正常 QPS** | 低（用户交互驱动） | 高（页面加载触发多个并发请求） |
| **缓存策略** | 通常不缓存 | CDN/浏览器强缓存 |
| **Referer 特征** | 可有可无 | 页面嵌入加载时通常有 Referer |
| **Cookie 特征** | 通常携带 | 不一定（跨域/第三方 CDN） |
| **误伤风险** | 高（业务逻辑复杂） | 低（纯资源下载） |
| **攻击成本** | 需要构造有效请求 | 简单 GET 即可 |

---

## 二、多层防御体系

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: 边缘层（CDN / Nginx 缓存）                         │
│  - CDN 缓存命中 → 源站零压力                                │
│  - 缓存键规范化（去除随机参数）                              │
│  - 带宽封顶告警                                              │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Nginx 层（连接/速率限制）                          │
│  - limit_conn（单 IP 并发连接限制）                          │
│  - limit_req（单 IP 请求速率限制）                           │
│  - Nginx 缓存（proxy_cache）                                 │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: WAF 层（智能 CC 防御）← 本项目补强重点             │
│  - 请求分类识别（静态/动态/API）                             │
│  - Bot 信号检测（UA/Referer/Cookie/Accept）                 │
│  - 分级限速（静态宽松、动态严格）                            │
│  - 渐进式惩罚（503 → 挑战 → 封禁）                          │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: 应用层（业务逻辑）                                 │
│  - 资源签名（URL 签名防盗链）                                │
│  - 水印/缩略图动态生成                                       │
│  - 用户行为验证（登录态校验）                                │
└─────────────────────────────────────────────────────────────┘
```

---

## 三、各层具体配置

### Layer 1: CDN 层（最关键）

**Cloudflare / 阿里云 CDN / AWS CloudFront 通用策略：**

```
1. 缓存规则
   - *.js *.css *.png *.jpg → 缓存 30 天
   - 忽略查询参数中的随机值（如 ?v=xxx ?t=xxx）
   
2. 带宽封顶
   - 单域名日带宽 > 100GB 触发告警
   - 单域名日带宽 > 500GB 自动回源限制
   
3. 防盗链
   - Referer 白名单（你的域名）
   - 空 Referer 可选放行/拒绝（根据业务）
```

### Layer 2: Nginx 层

```nginx
# 在 http 块中定义限制区域
limit_conn_zone $binary_remote_addr zone=conn_limit:10m;
limit_req_zone $binary_remote_addr zone=req_limit:10m rate=100r/s;

server {
    # 静态资源：并发连接和请求速率限制
    location ~* \.(jpg|jpeg|png|gif|css|js|woff)$ {
        # 单 IP 最多 20 个并发连接
        limit_conn conn_limit 20;
        
        # 单 IP 平均速率 50r/s，突发 100 个请求缓冲
        limit_req zone=req_limit burst=100 nodelay;
        
        expires 30d;
        add_header Cache-Control "public, immutable";
        
        # 可选：Nginx 本地缓存
        # proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=static_cache:100m;
    }
}
```

### Layer 3: WAF 层（本项目增强）

**config.lua 推荐配置：**

```lua
-- ============================================
-- 场景：静态资源为主站点（图片站 / 下载站）
-- ============================================
CCEnhanced = "on"

-- 全站全局：60秒2000次（约33 QPS/IP）
CCGlobalRate = "2000/60"

-- 静态文件：60秒600次（约10 QPS/IP）
-- 注意：一个页面可能加载 20+ 个静态资源
-- 正常用户：页面加载集中在 2-3 秒内完成
-- 攻击者：持续高并发
CCStaticRate = "600/60"

-- 无 Referer 静态请求：更严格（疑似盗链/直接刷）
CCStaticNoRefererRate = "200/60"

-- 无 Cookie 静态请求：也较严格
CCStaticNoCookieRate = "300/60"

-- 动态请求：60秒120次（约2 QPS/IP）
CCDynamicRate = "120/60"

-- API 接口：稍宽松（SPA 应用可能有较多 API 调用）
CCApiRate = "300/60"

-- POST 收紧（写操作更敏感）
CCPostMultiplier = 0.5

-- 渐进惩罚开启
CCProgressive = "on"
```

**场景化配置速查表：**

| 场景 | CCGlobalRate | CCStaticRate | CCDynamicRate | 说明 |
|------|-------------|--------------|---------------|------|
| 企业官网 | 2000/60 | 600/60 | 120/60 | 静态资源多，动态少 |
| 电商平台 | 5000/60 | 2000/60 | 300/60 | 高并发，API调用多 |
| 图片/视频站 | 3000/60 | 1000/60 | 60/60 | 带宽敏感，静态严格 |
| API 服务 | 3000/60 | 300/60 | 600/60 | API为主，静态少 |
| 高防场景 | 1000/60 | 300/60 | 60/60 | 被攻击时临时收紧 |

---

## 四、静态文件 CC 的识别策略

### 4.1 请求分类逻辑

本项目增强版自动将请求分类为：
- **static**：`.js` `.css` `.png` `.jpg` 等 + `/static/` `/assets/` 路径
- **api**：`/api/` `/ajax/` `/graphql` 路径 + 非静态路径的 `.json`
- **upload**：`multipart/form-data`
- **dynamic**：其他所有请求

### 4.2 Bot 信号评分

| 信号 | 分值 | 说明 |
|------|------|------|
| 无 User-Agent | +3 | 极可能是脚本 |
| 无 Referer | +1 | 直接访问/嵌入盗链 |
| Accept = */* | +1 | 不指定 MIME 类型 |
| 无 Accept-Language | +1 | 浏览器通常携带 |
| 无 Cookie | +1 | 非首次访问应携带 |
| 自动化 UA（curl/python等） | +3 | 明确脚本特征 |

**风险等级影响 CC 阈值：**
- Low（0-2分）：正常阈值
- Medium（3-4分）：阈值降低 40%
- High（5+分）：阈值降低 70%

### 4.3 渐进式惩罚流程

```
首次超限 → 503 Service Unavailable
    │
    ▼
再次超限（60秒内）→ 302 Set-Cookie 挑战
    │    └─ 客户端必须携带 Cookie 才能继续访问
    │    └─ 简单脚本无法自动完成
    ▼
第三次超限 → 封禁 IP 5 分钟
    │
    ▼
第四次及以上 → 封禁 IP 1 小时
```

---

## 五、特殊场景处理

### 5.1 搜索引擎爬虫

```lua
-- 在 ipWhitelist 中加入搜索引擎 IP 段
-- 或通过 User-Agent 识别（但 UA 可伪造）
ipWhitelist = {
    "127.0.0.1",
    "10.0.0.0/8",
    -- Googlebot（需通过 DNS 反向验证）
    -- Bingbot
    -- 百度蜘蛛
}
```

**更好的方案**：使用 `robots.txt` + CDN 的爬虫管理功能，而非 WAF 层面放行。

### 5.2 合法高并发场景

```lua
-- 场景：前端构建工具（Webpack/Vite）开发时大量请求
-- 方案：开发环境关闭 CC，或提高阈值

-- 场景：监控系统（Prometheus/Grafana）定期抓取
-- 方案：将监控 IP 加入白名单
ipWhitelist = {
    "127.0.0.1",
    "10.0.0.0/8",        -- K8s 内网
    "172.16.0.0/12",
    "100.64.0.0/10",     -- 阿里云 SLB
}
```

### 5.3 缓存击穿防御

攻击者使用随机参数绕过 CDN 缓存：
```
GET /style.css?v=random123
GET /style.css?v=random456
```

**防御策略：**
1. **CDN 层**：配置忽略 `v` / `t` / `_` 等缓存无关参数
2. **Nginx 层**：使用 `$uri`（不含参数）做 CC key
3. **WAF 层**：本项目使用 `utils.classify_request()` 时，`uri` 不含查询参数

---

## 六、监控与调优

### 6.1 关键指标

```bash
# 查看 CC 拦截统计
tail -f /u/medsci/logs/nginx/cc_ban.log

# 按命中类型统计
grep -oP '\[CC-[^\]]+\]' /u/medsci/logs/nginx/*_sec.log | sort | uniq -c | sort -rn

# 查看被封禁 IP
#（通过管理接口）curl "http://localhost/waf-admin?action=stats&ip=x.x.x.x"

# 查看当前请求分类情况（加响应头后）
# X-WAF-Req-Type: static/dynamic/api/upload
```

### 6.2 调优 checklist

- [ ] 上线初期 `CCEnhanced = "on"` 但调高阈值，观察 3 天
- [ ] 检查日志中 `[CC-*-limit]` 的命中情况
- [ ] 确认白名单 IP（负载均衡、CDN、监控）已配置
- [ ] 确认搜索引擎/合法爬虫未被误伤
- [ ] 观察 `X-WAF-CC-Status` 响应头，了解拦截分布
- [ ] 逐步收紧阈值至目标值

### 6.3 应急响应

```lua
-- 遭受大规模 CC 攻击时的紧急配置
CCEnhanced = "on"
CCGlobalRate = "500/60"        -- 全站急剧收紧
CCStaticRate = "100/60"        -- 静态资源严格限制
CCStaticNoRefererRate = "30/60" -- 无 Referer 几乎禁止
CCDynamicRate = "30/60"        -- 动态请求严格限制
CCProgressive = "on"
CCBanDuration1 = 300           -- 首次即封禁 5 分钟
CCBanDuration2 = 1800          -- 二次封禁 30 分钟
CCBanDuration3 = 86400         -- 三次封禁 1 天
```

---

## 七、与主流 WAF 的能力对齐

| 能力 | Cloudflare | AWS WAF | 本项目增强后 |
|------|-----------|---------|-------------|
| 请求分类 | ✅ 自动 | ✅ 手动配置 | ✅ 自动（静态/动态/API/上传） |
| Bot 检测 | ✅ ML + JS Challenge | ✅ CAPTCHA | ⚠️ 基础信号评分（可扩展） |
| 分级限速 | ✅ | ✅ | ✅ |
| 渐进惩罚 | ✅ Challenge → Block | ✅ Rate limit → Block | ✅ 503 → Challenge → Ban |
| 缓存击穿防护 | ✅ CDN 参数忽略 | ✅ CloudFront | ⚠️ 需配合 CDN/Nginx |
| 分布式 | ✅ 全球边缘 | ✅ 区域 | ❌ 单机（可扩展 Redis） |

> ⚠️ 表示需要额外配置或能力有限，建议配合 CDN/Nginx 层使用。
