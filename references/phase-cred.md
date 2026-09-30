# P1 凭据就绪阶段（DeepBounty）

> 目标：开挖前把凭据备齐、验活、归并，过 cred_gate 硬门禁。
> 本阶段是 DeepBounty 第一核心——**凭据不断供，挖掘才有意义**。
> 详细 SOP 见 [cred-playbook.md](cred-playbook.md)，此处为阶段编排。

## 为什么单列一个阶段（审计教训）

tyang-skill2 三轮审计：匿名 cookie 指纹致身份爆炸（aliyun 122 个假身份）、
344 个从未验活却 success、138 个过期 JWT 却 success、挖掘期 0/38997 凭据追溯。
根因：凭据管理是挖掘的附属品。DeepBounty 把它提为独立阶段 + 硬门禁。

## 步骤

### 1. 凭据汇集（多来源）

| 来源 | 命令 |
|---|---|
| 用户下发账号密码 | `cred_vault.py add-account` |
| 用户下发 Cookie/Token | `cred_vault.py add-session` |
| 用户下发完整登录请求包 | `cred_vault.py add-packet`（解析原文） |
| 流量中提取 | `extract_credentials.py` 后 `cred_vault.py import-config` |
| 历史项目 sessions.json | `cred_vault.py import-legacy`（按 username/user_id 归并） |

归并纪律：**身份 = username/user_id**，不是凭据值指纹；匿名设备指纹 cookie
（`_did/did/kwpsecprodu` 等，见 common.ANON_COOKIE_NAMES）永远不算身份。

### 2. 角色标注与 host 绑定

- 每个身份标角色：`attacker` / `victim` / `admin`（越权测试必需双账号）；
- `cred_vault.py bind-host` 绑定适用 host（凭据不串台）。

### 3. 区分度验活（cred_verify.py）

```powershell
python .claude\skills\deepbounty\scripts\cred_verify.py --project <id>
```

- **带凭据 vs 不带凭据**请求同一需登录端点，响应无区分度 = 不判活（保持 unknown）；
- JWT 强制解析 exp：过期直接 `expired`；
- 有 login_packet/token_endpoint 的尝试重放续期；
- 匿名基线恒 alive（用于未授权面对比）。

### 4. 硬门禁（cred_gate.py）

```powershell
python .claude\skills\deepbounty\scripts\cred_gate.py --project <id>
```

- 每个目标 host **≥1 个 alive 非匿名身份**，否则硬错误（阻断开挖）；
- `unknown` 状态身份 = 硬错误（必须先验活）；
- 同 host 无 ≥2 个 alive 同级账号 → coverage.json 标 `authz_blocked=true`
  （AUTHZ 叶子后续记 blocked，**禁止 tested_not_found**）；
- 产出 `cred/coverage.json`：每 host 的 `alive_cred_ids`（miner 取证消费）。

### 5. 凭据不足 → cred-steward

门禁不过：调度 **deepbounty-cred-steward** 子代理——
登录包重放续期 / 引导用户提供 / 人工登录承载（验证码/扫码/SSO）。
用户明确说"没有账号"→ 未授权面挖掘，AUTHZ 全面 blocked，config 记 `no_cred_ack`。

## 出口门禁

- [ ] `cred_gate.py` exit 0（或 acknowledged 逐条登记）；
- [ ] coverage.json 每 host 有 alive_cred_ids；
- [ ] 双账号需求已确认（有越权面时）；
- [ ] state.json.phase_status.credentials = done。

## 挖掘期持续保障（非本阶段但契约在此）

- miner 只用 alive 身份，带全 `auth.cookie`+`auth.headers`；
- 401/跳登录 → 停测该身份，调度 cred-steward 救援，**不得拿失效身份产出"安全"结论**；
- 矩阵每条目强制 `cred_id`（evidence_gate 校验追溯率 ≥95%）。
