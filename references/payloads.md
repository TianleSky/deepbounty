# Payload 库指针（DeepBounty）

> DeepBounty **不重写 payload 库**——直接引用本地 Claude-BugHunter 缓存的 60+ hunt-* 技能
> （含各漏洞类 payload 表与绕过表）。本文件是指针索引。

## 本地技能库位置

```
C:\Users\Administrator\.claude\plugins\cache\elementalsouls\claude-bughunter\2.1.0\skills\
C:\Users\Administrator\.claude\skills\   （同名技能的用户级副本）
```

## 按漏洞类索引（miner/bypass 按需 Read）

| 漏洞类 | 技能路径（skills/ 下） |
|---|---|
| SQL 注入 | hunt-sqli/SKILL.md |
| NoSQL 注入 | hunt-nosqli/SKILL.md |
| XSS / DOM | hunt-xss/SKILL.md、hunt-dom/SKILL.md |
| SSRF | hunt-ssrf/SKILL.md |
| XXE | hunt-xxe/SKILL.md |
| SSTI | hunt-ssti/SKILL.md |
| 命令注入/RCE | hunt-rce/SKILL.md |
| LFI/路径穿越 | hunt-lfi/SKILL.md |
| 文件上传 | hunt-file-upload/SKILL.md |
| 反序列化 | hunt-deserialization/SKILL.md |
| JWT | hunt-jwt-crypto/SKILL.md |
| 越权/IDOR | hunt-idor/SKILL.md |
| 认证绕过/ATO | hunt-auth-bypass/SKILL.md、hunt-ato/SKILL.md |
| MFA/验证码 | hunt-mfa-bypass/SKILL.md、hunt-captcha-bypass/SKILL.md |
| 忘记密码 | hunt-forgot-password/SKILL.md |
| 会话 | hunt-session/SKILL.md |
| CSRF/CORS/点击劫持 | hunt-csrf/SKILL.md、hunt-cors/SKILL.md、hunt-clickjacking/SKILL.md |
| 开放重定向 | hunt-open-redirect/SKILL.md |
| Host 头 | hunt-host-header/SKILL.md |
| HTTP 走私/缓存投毒 | hunt-http-smuggling/SKILL.md、hunt-cache-poison/SKILL.md |
| 竞态 | hunt-race-condition/SKILL.md |
| 业务逻辑 | hunt-business-logic/SKILL.md |
| GraphQL/gRPC/WebSocket | hunt-graphql/SKILL.md、hunt-grpc/SKILL.md、hunt-websocket/SKILL.md |
| OAuth/SAML/LDAP | hunt-oauth/SKILL.md、hunt-saml/SKILL.md、hunt-ldap/SKILL.md |
| 框架专项 | hunt-springboot/SKILL.md、hunt-nextjs/SKILL.md、hunt-nodejs/SKILL.md、hunt-aspnet/SKILL.md、hunt-laravel/SKILL.md、hunt-sharepoint/SKILL.md |
| 源码泄露/API | hunt-source-leak/SKILL.md、hunt-shadow-api/SKILL.md、hunt-api-misconfig/SKILL.md、hunt-spa-api/SKILL.md |
| 其他 | hunt-misc/SKILL.md、hunt-exceptional-conditions/SKILL.md |

## 增量手册（vuln-recipes/，14 家对标吸收）

> 对标矩阵见 `docs/skill-compare.md`。下表每类一个增量手册，只收 Claude-BugHunter 基线**之外**的
> payload 族/判定逻辑/案例；miner 测某类前按「基线技能 + 增量手册」双读。

| 漏洞类 | 增量手册 | 主要吸收来源 |
|---|---|---|
| SQL 注入 | vuln-recipes/sqli.md | communitytools 指纹路由 + strix 五条证据链 |
| NoSQL 注入 | vuln-recipes/nosqli.md | communitytools Mongo 五手法 + strix 7 后端 |
| XSS | vuln-recipes/xss.md | pentest-agents 判定树 + communitytools 影响链 |
| 命令注入 | vuln-recipes/cmdi.md | strix argument_injection（独家四原语） |
| SSRF | vuln-recipes/ssrf.md | Agentic-BH triage 硬规则 + BountyGrimoire 参数优先级 |
| XXE | vuln-recipes/xxe.md | BountyGrimoire 上传链 + Agentic-BH OOB-DTD |
| 路径穿越 | vuln-recipes/path-traversal.md | communitytools 场景族 + strix 执行链 |
| 文件上传 | vuln-recipes/file-upload.md | Agentic-BH multipart 混淆 + AutoHunter 三分法 |
| SSTI | vuln-recipes/ssti.md | strix 指纹差分表 + Argus 大数判定 |
| ELI | vuln-recipes/eli.md | strix SpEL + pentest-agents 速查（补强） |
| JWT | vuln-recipes/jwt.md | communitytools 13 场景全谱 |
| 用户枚举 | vuln-recipes/user-enum.md | communitytools oracle + AutoHunter 拒收口径 |
| 越权 | vuln-recipes/authz.md | AutoHunter 无害写证法五分类（独家） |
| IDOR | vuln-recipes/idor.md | Argus 无效 id 基线 + pentest-agents 操纵手法 |
| 优惠/积分/抽奖 | vuln-recipes/prize.md | VEGA 状态机 + communitytools 场景族 |
| 竞态 | vuln-recipes/race.md | communitytools PREDICT/PROBE/PROVE |
| 重放 | vuln-recipes/replay.md | communitytools 多通道 + Claude-BugHunter 轮换审计 |
| 验证码/短信 | vuln-recipes/sms-captcha.md | communitytools 优先序 + AutoHunter 三分法 |
| 开放重定向 | vuln-recipes/open-redirect.md | BountyGrimoire 绕过矩阵 + strix OAuth 升级链 |
| CORS | vuln-recipes/cors.md | Agentic-BH 分级模型 + communitytools 绕过族 |
| 敏感信息泄露 | vuln-recipes/info-leak.md | VEGA 中国场景正则 + strix Triage Rubric |

## Payload 新鲜度警示（2026 时效，吸收 Claude-BugHunter arsenal）

以下经典 payload 对**现代版本组件已失效**，打之前先指纹前端/解析器版本，别在已修复的解析器上烧 bypass 次数：

| Payload 族 | 已失效环境 | 仍有效环境 |
|---|---|---|
| CL.TE / TE.CL 走私经典包 | Nginx ≥1.21、Caddy 2.x、Envoy ≥1.20 | HAProxy ≤2.4、老 F5 BIG-IP、Citrix ADC、AWS ALB 特定配置、Apache Traffic Server |
| XXE 经典 SYSTEM 实体 | Python lxml ≥5.x（默认静默丢弃） | Java SAX、PHP DOMDocument+LIBXML_NOENT、.NET XmlDocument+XmlResolver、lxml <5.0、Ruby Nokogiri+DTDLOAD、SOAP/SAML/Office 解析长尾 |
| `javascript:` 链于 `<a href>` | 现代 Chrome（无显式手势即拦） | 内嵌 WebView、Electron、老 Edge |
| `data:text/html` 顶层导航 | 现代浏览器导航上下文剥离 | 部分 iframe/子框架上下文 |
| CRLF 注入 `Location:` 头 | 多数反代已规范化 | 裸应用服务器/老框架 |

指纹动作：`curl -sI` 看 `Server`/`Via` 链 + TLS 指纹；XML 入口先确认解析器栈再选 payload。

## Payload 新鲜度警示（2026 口径，吸收 Claude-BugHunter arsenal）

以下经典 payload 对**现代组件已失效或受限**，用前先指纹前端/解析器版本，别在已被前门拒绝的 payload 上烧时间：

| Payload 族 | 已失效/受限环境 | 仍然有效的环境 |
|---|---|---|
| CL.TE / TE.CL 走私 | Nginx ≥1.21、Caddy 2.x、Envoy ≥1.20 | HAProxy ≤2.4、老 F5 BIG-IP、Citrix ADC、AWS ALB 特定配置、Apache Traffic Server |
| XXE 经典 SYSTEM 实体 | Python lxml ≥5.x（默认静默丢弃） | Java SAX、PHP DOMDocument+LIBXML_NOENT、.NET XmlDocument+XmlResolver、lxml <5.0、Ruby Nokogiri+DTDLOAD、SOAP/SAML/Office 解析长尾 |
| `javascript:` in `<a href>` | Chrome（需显式用户手势） | 内嵌 WebView、Electron、老 Edge |
| `data:text/html` 顶层导航 | 现代浏览器导航上下文剥离 | 部分 iframe/子框架上下文 |
| CRLF in `Location:` | 多数反向代理已规范化 | 自建/老旧代理链 |

指纹先行：`curl -sI` 看 `Server`/`Via` 链 + TLS 指纹；XXE 先判解析器生态再选 payload。

## 使用纪律

1. miner 测某漏洞类前，Read 对应技能文件取 payload 表与判定要点；
2. bypass 子代理取各技能的绕过章节（WAF bypass 表）+ `references/waf-bypass.md` 专项；
3. 技能与 ref-repos 内容**只读引用**——发现新手法写 shared_knowledge / memory-global，不改源文件；
4. 技能与 checkpoints.md 冲突时，以 checkpoints.md（机读门禁）为准。
