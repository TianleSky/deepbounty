# 敏感信息泄露增量手册（DeepBounty 吸收版）

> 基线：Claude-BugHunter `hunt-source-leak/SKILL.md` + `hunt-api-misconfig/SKILL.md`。
> 无强制检查点，按通用证据标准 + 打码规则（evidence-standard）。

## 最优来源

- VEGA `agents/vega-leak.md`（**中国场景密钥正则 + 误报过滤 + 严重性校准**，独家本地化）
- strix `information_disclosure.md`（Triage Rubric：Critical→Informational 分级）
- pentest-agents `skills/hunt-info-disclosure/SKILL.md`（866 行）+ `wordlists/secret-patterns.txt`
- AutoHunter `prompts.py`（EduSRC「死规矩四类 + 公开接口排除」口径）

## 增量 1：中国场景密钥正则（VEGA，本地化独家）

- 阿里云 `LTAI[A-Za-z0-9]{12,}`、腾讯云 `AKID[A-Za-z0-9]{32,}`、华为云/火山引擎 AK/SK 格式
- 微信支付商户号/APIv3 密钥、支付宝应用私钥（`MII...` PKCS8 头）
- 微信小程序 AppSecret（32 位 hex）、公众号 secret
- 钉钉/企业微信/飞书 webhook 与 appsecret
- 短信平台（阿里云通信/云片/Submail）APIKey
- 高德/百度地图 AK（注意：前端地图 AK 多数**不算洞**，需配合未限制 referer 且可盗刷额度才报）

## 增量 2：误报过滤（VEGA + AutoHunter 合订）

不报清单：示例/占位密钥（`your-api-key`、`AKIAIOSFODNN7EXAMPLE` 类公开示例）、
公开文档截图中的历史失效 key、前端公开标识（GA ID、Sentry DSN 公开版）、
已确认公开的接口文档数据。AutoHunter 口径：**公开接口返回公开数据不算泄露**。

## 增量 3：Triage Rubric（strix 分级）

| 级别 | 标准 |
|---|---|
| Critical | 有效云 AK/SK、数据库凭据、私钥——可直接接管基础设施 |
| High | 有效第三方服务密钥（支付/短信）、大量 PII（>1 万条） |
| Medium | 内部接口文档/路径、少量 PII、版本指纹带已知 CVE |
| Low | 堆栈跟踪、调试信息、硬编码内部域名 |
| Informational | 服务器 banner、公开可查信息 |

验证纪律：密钥类必须**验活**（调对应 API 签名请求一次，无害只读操作如 ListBuckets），
验活失败降级「疑似失效密钥」；验活请求与响应进证据（打码后 8 位）。

## 增量 4：高发入口（pentest-agents hunt-info-disclosure）

JS bundle 源 map（`.js.map`）、`.git`/`/.env`/`/.svn`、Swagger/Actuator 暴露、
报错堆栈、备份文件（`.bak`/`~`/`.swp`）、目录列表、注释中的内网地址。
配 deepbounty `param_discover.py` 的 JS 解析链路使用。

## 判定纪律

- 所有密钥/PII 证据按 evidence-standard 打码（前 4 后 4）
- 单接口返回 <5 条非敏感字段标 Informational，不进验证队列
