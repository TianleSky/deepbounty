# 凭据 Playbook（DeepBounty）

> 凭据子系统的 SOP 权威文档。核心契约：**未验活不得消费、无 alive 身份不得开挖、越权必须双账号、每条矩阵账目必须 cred_id 追溯**。

## 数据模型

### cred/accounts.json — 账号注册表（真实身份维度）

归并键 = `username` / `user_id`（**不是凭据值**——同一账号换 Cookie 只刷新会话，不新建身份）。

| 字段 | 说明 |
|---|---|
| `account_id` | `ACCxxxx`，稳定编号 |
| `role` | `attacker` / `victim` / `admin` / 自定义；越权测试靠 role 配对 |
| `username` / `user_id` / `password` | 账号主体信息 |
| `hosts` | 该账号适用的 host 集合 |
| `source` | `user_provided` / `traffic_extract` / `config_test_accounts` / `login_packet` |
| `login_packet` | 完整登录请求包 `{method,url,headers,body}`，失效重放续期用 |

### cred/sessions.json — 会话池 v2（凭据维度）

| 字段 | 说明 |
|---|---|
| `cred_id` | `CREDxxxx`，稳定编号；**矩阵条目 `cred_id` 字段引用它** |
| `account_id` | 归属账号 |
| `status` | 状态机：`unknown`（导入/刷新后待验）→ `alive` / `expired` / `revoked`。**只有 `alive` 可消费** |
| `is_anonymous` | 匿名/设备指纹凭据标记（`_did`/`did` 等黑名单），仅作未登录基线，**永不算身份** |
| `auth` | `{cookie, headers}`——消费时 cookie 与自定义认证头**必须全带** |
| `token_exp` | JWT exp 死期（cred_verify 强制解析，过期直接 `expired` 不发包） |
| `verify` | 最近一次验活记录 `{at, method, probe_url, verdict_reason}` |
| `token_endpoint` | 流量里识别出的凭据发放接口（自动续期备选） |

## 验活标准（区分度探针）

`cred_verify.py` 的判定逻辑，任何人不得绕过：

1. **JWT exp 先行**：凭据里发现过期 JWT → 直接 `expired`，不发包。
2. **双发对比**：同一探针带凭据 / 不带凭据各发一次：
   - 响应一致（状态码同 + 相似度 ≥0.98）→ **探针无区分度 → 保持 `unknown`，不判活**；
   - 带凭据呈未登录特征（401/403/跳登录页/响应含"未登录"）→ `expired`；
   - 带凭据 2xx 且与不带凭据有区分 → `alive`。
3. **续期自救**：`expired` 且有 `login_packet`/`token_endpoint` → 自动重放刷新后重验。
4. 探针选择：优先 `session.probe_url`；否则从 url-inventory 挑该 host 的 GET api/page（排除 login/logout/captcha/register）。全 POST 网关型必须人工 `--probe-url` 指定。

## 挖掘前门禁（cred_gate）

`cred_gate.py` 写入 `state.json.gates.cred_gate`，`blocking_count==0` 才准进入挖掘：

- **[身份覆盖]**（硬）任务范围每个 host ≥1 个 alive 非匿名身份；
- **[验活前置]**（硬）不存在 `unknown` 非匿名身份；
- **[双账号就绪]**（软→行为强制）无 host 具备 ≥2 个 alive 不同账号时，`coverage.json.authz_blocked=true` → 任务树把所有 AUTHZ 叶子置 `blocked`，**禁止记 tested_not_found**。

## 派生不得覆盖原始满罐

同一身份（同一 `uid` / `sessionid` / `user_id`；没有这些键就按账号归并键）在 `proxy-logs/requests/*.log` 里已有一条业务成功的原始请求时：

- 入库 Cookie 以那条原始请求的 Cookie 为底。
- SSO / `Set-Cookie` / 登录包重放只允许追加新名字，或更新同名项的值。
- 禁止用派生出的短串删掉原始请求里有、派生结果里没有的名字。
- 原始请求里的认证头同样处理，不单写死 Cookie。
- 没有原始成功包时，才使用用户给的串或派生串，并在 `notes` 写「无原始满罐」。

「业务成功」：不是 401、不是跳登录、响应也没有「未登录 / 登录过期 / 登录失效」。空列表但原始响应仍是登录成功，算成功，不得因此换凭据或判越权。两个身份的 Cookie 禁止并成一串。

## miner 消费契约

1. 只从 `cred/coverage.json` 的 `alive_cred_ids` 取身份；按 host 匹配。Cookie 和认证头只从 `cred/sessions.json` 读，禁止另存截断的 cookie 文件当唯一来源。
2. 重放必须带全 `auth.cookie` + `auth.headers`。挖每个 URL 前，用该 URL 日志里最近一条业务成功的原始请求做一次对照（不加 payload）：重放仍成功则用库存这串；原始成功而重放变成未登录，则改用原始请求里的 Cookie 再重放一次，成功后用原始这串挖掘，并让 cred-steward 把库补成「原始名字 ∪ 派生更新」。没有原始包的 URL 沿用验活结果。
3. 矩阵每条账目填 `cred_id`（用了哪个身份）；未授权面测试填 `unauthenticated` 基线的 cred_id 或 `none`。越权发了两份身份时，`cred_id` 填主身份，`notes` 写上另一个 `cred_id`。通用漏洞用能复现该 URL 原始登录信号的那一份 alive。
4. 响应明确是未登录 / 登录过期 / 登录失效（含业务码，不限于 401）→ 立即停用该身份，本批剩余 URL 不再用它，格子记 `doubtful`（`death_cause=precondition`），报主代理调度 cred-steward。**禁止记 tested_not_found，禁止把同一份死 Cookie 铺满后续叶子。**
5. 报告请求包必须贴本次实际发送的 Cookie / Token 原文。禁止写成「全量因子」、文件路径或「见 sessions.json」。

## 双账号操作规范（越权前提）

- `attacker`：攻击者视角账号；`victim`：受害者账号（其数据作为"他人数据"标的）。
- 两账号必须**同 privilege 层级**（都是普通用户）测水平越权；垂直越权用 `admin` 资源 + `attacker` 低权身份。
- victim 侧产生的私有数据（订单/资料/消息 ID）是 attacker 侧 IDOR 测试的弹药——cred-steward 负责在入库时向主代理说明两账号已各自准备了哪些私有对象。
