# 重放增量手册（DeepBounty 吸收版）

> 基线：Claude-BugHunter `hunt-session/SKILL.md` 相关章节。检查点映射：REPLAY001 重放成功证明。

## 最优来源

- communitytools（多通道重放场景：订单确认/OTP/OAuth state/SAML）
- Claude-BugHunter `hunt-session`（refresh-token 轮换 + 家族吊销，OAuth BCP 口径）
- VEGA `agents/vega-logic.md`（登出后 Token/支付重放 curl 验证脚本）

## 增量 1：多通道重放场景（communitytools）

| 通道 | 重放点 | 判定 |
|---|---|---|
| 订单/支付 | 支付成功回调重放（notify_url） | 重复到账/重复发货 |
| OTP | 同一验证码多次提交 | 多次通过即 REPLAY001 |
| OAuth | state/code 二次使用 | code 换两次 token |
| SAML | Assertion 重放 | 同一 Response 二次登录成功 |
| 签名接口 | 截获签名请求原样重发 | timestamp/nonce 不校验即通过 |
| 消息队列/WebSocket | 帧重放 | 重复消费 |

## 增量 2：Token 生命周期审计（Claude-BugHunter，OAuth BCP）

- **refresh-token 轮换**：旧 refresh token 使用后应失效——重放旧 token 成功 = 漏洞
- **家族吊销**：检测到重放时应吊销整个 token 家族；不吊销 = 检测缺失
- **登出失效**：登出后 access token/会话立即重放（VEGA 的 curl 脚本模式：
  登录→抓包→登出→原样重放→仍 200 = REPLAY001 通过）

## 增量 3：防重放机制测绘清单

逐项检查目标缺哪层：timestamp 窗口 / nonce 一次性 / 签名含 body hash /
序列号递增 / 一次性 token。**缺哪层就报哪层**，报告写清「缺失机制」而非笼统「可重放」。

## 判定纪律

- REPLAY001：同一请求（含签名/token/验证码）原样重发 ≥2 次均成功，且第二次产生实际业务效果
- 幂等 GET 接口不算重放漏洞（无业务效果）；必须落到写操作或受限资源消耗
