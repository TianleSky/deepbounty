# CORS 增量手册（DeepBounty 吸收版）

> 基线：Claude-BugHunter `hunt-cors/SKILL.md`（凭证硬规则已强）。无强制检查点，按通用证据标准。

## 最优来源

- communitytools（`cors-quickstart`/`cheat-sheet` + `scenarios/rest/cors-misconfiguration.md`）
- Agentic-Bug-Hunter `bughunter/tools/cors_scanner.py`（ACAO/ACAC 分级严重度模型，可执行）
- Claude-BugHunter hunt-cors（「仅凭证可读才 High」硬规则）

## 增量 1：分级严重度模型（Agentic-Bug-Hunter cors_scanner.py）

| ACAO | ACAC | 判定 |
|---|---|---|
| `*` | true | 浏览器忽略（非法组合），**不算** |
| `*` | false/无 | 仅公开数据，信息级 |
| 反射 Origin | true | **高危**：任意站带凭证读响应 |
| 反射 Origin | false | 中危：可读公开响应 |
| 白名单绕过（子域/后缀/null） | true | **高危**（等同反射） |
| `null` | true | 高危：sandbox iframe/data: URL 可触发 |

## 增量 2：白名单绕过族（communitytools cheat-sheet）

- 子域信任：`evil.trusted.com`（配合子域接管/XSS）
- 后缀拼接：`trusted.com.evil.com`
- 前缀拼接：`eviltrusted.com`（未锚定开头）
- 下划线/特殊字符：`trusted_com.evil.com`（部分解析器规范化差异）
- `null` origin：sandbox iframe、data: URL、file: 页面
- 协议降级：`http://trusted.com`（白名单只查主机名时）

## 增量 3：利用前提审计（Claude-BugHunter 硬规则强化）

报高危前必须确认：
1. 目标接口返回**敏感数据**（用户信息/token/订单——公开数据不算）
2. 凭证模式真实生效（Cookie/Authorization 头随请求发出且响应可读）
3. 受害者场景成立（登录态用户访问攻击者页面）
三缺一则降级。「仅凭证可读才 High」——无凭证的 CORS 反射最多中危。

## 判定纪律

- 证据 = 恶意 Origin 请求 + 响应头（ACAO 反射 + ACAC:true）+ 带凭证实测可读敏感数据的响应体
- cors_scanner.py 可直接跑批量 Origin 变体，输出分级结果贴矩阵 basis
