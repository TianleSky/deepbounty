# 端点能力 × 漏洞类兼容矩阵（capability matrix，DeepBounty）

> 借 Argus EndpointCapability：按端点能力画像生成适用漏洞类白名单，杜绝无意义组合。
> 机读实现：`scripts/capability_matrix.py`（COMPAT_RULES），产出 `endpoint-capabilities.json`。
> 本文档是规则的人类可读说明；改规则必须同步改脚本。

## 端点能力画像字段

| 字段 | 来源 | 说明 |
|---|---|---|
| methods | url-inventory | GET/POST/... |
| params[].name/source/type/sample_value | params/{uid}.json | 参数名/位置(query/body/json)/类型/样本值 |
| content_types | requests/{uid}.log 头 | 请求 Content-Type 集合 |
| has_upload | 头含 multipart/form-data | 文件上传面 |
| has_xml | 头或 body 含 xml | XXE 前提 |
| has_json | 头含 json | NoSQL/JSON 注入面 |
| has_jwt | 报文含 JWT 格式 token | JWT 测试前提 |
| auth_seen | 认证头/401/403 记录 | 越权面前提 |
| path_lower | URL path 小写 | 业务路径线索 |

## 兼容规则（漏洞类 ← 判定条件）

| 漏洞类 | 适用条件 |
|---|---|
| SQL注入 | 有参数 |
| NoSQL注入 | 有参数 且（JSON 体 或 参数名∈filter/query/where/search/sort/order） |
| XSS | 有参数（反射面） |
| 命令注入 | 有参数（命令相关名或 URL 类名加权） |
| SSRF | 参数名∈URL 类词表（url/link/callback/webhook/...）或样本值是 URL |
| XXE | has_xml |
| 路径穿越 | 参数名∈文件路径类词表（file/path/filename/template/...） |
| 文件上传 | has_upload 或参数名∈上传类词表 |
| SSTI / ELI | 有参数（回显面） |
| JWT | has_jwt |
| 用户枚举 | path 含 login/register/reset/check/exists/send 等 |
| 越权 | auth_seen 或含 ID 类参数 |
| IDOR | 含 ID 类参数（id/uid/order_id/*_id/...） |
| 优惠/积分/抽奖重复使用 | path 含 order/pay/coupon/prize/draw/points/... |
| 竞态 | 业务路径 或参数名∈count/num/amount/quantity/stock/balance/price |
| 重放 | 业务路径 或短信验证码路径 |
| 验证码/短信绕过 | path 含 sms/captcha/verify/code/otp |
| 开放重定向 | 参数名∈redirect/return/next/goto/jump/target/url/link |
| CORS | 全部接口（响应头审查） |
| 敏感信息泄露 | 全部接口（响应审查） |

## 使用纪律

- 白名单是**下限**：miner 发现白名单外某类确实适用（如响应渲染 XML 但请求非 XML），
  可补测并在矩阵补条目——全面性优先；
- 白名单外类型**不进任务树**（防无意义组合浪费预算）；
- 参数级细化：叶子 = 参数×漏洞类，某参数不适用可在矩阵记 not_applicable（basis 简述）。
