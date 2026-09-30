# IDOR 增量手册（DeepBounty 吸收版）

> 基线：Claude-BugHunter `hunt-idor/SKILL.md`。检查点映射：归 AUTHZ 前缀（AUTHZ002 水平越权为主）。
> 参数命中记忆：`memory-global/idor-params-hit.json`（全局复用高命中参数名）。

## 最优来源

- pentest-agents `skills/hunt-idor/SKILL.md`（791 行：ID 操纵/方法变异/版本降级）
- Argus `agents/lats/actions.py`（**无效 id 基线判定**，防公开资源误报）
- AutoHunter `prompts.py` + `write_proof.py`（看→改/删→量化规模升级链 + 无害证法）
- Agentic-Bug-Hunter `bughunter/tools/h1_idor_scanner.py` 等专用脚本

## 增量 1：无效 id 基线（Argus，防误报关键）

换 id 前先发**不存在的 id**（如 `999999999`）：
- 无效 id 也返回 200 + 数据 → 公开资源/兜底页，**不是 IDOR**，直接排除
- 无效 id 返回 404/空，有效他人 id 返回 200 + 数据 → 真 IDOR
此判定进 authz_probe.py 的基线组，miner 手工测时同样执行。

## 增量 2：ID 操纵全手法（pentest-agents）

- 数值 ±1、批量枚举、负数、0、超大数（int 溢出）
- UUID 不可猜时的替代：泄露点搜索（响应/JS/日志/邮件链接/导出文件中的他人 UUID）
- 编码变体：Base64、URL 双编码、数组（`id[]=1&id[]=2`）、JSON 嵌套（`{"user":{"id":2}}`）
- 参数污染：HPP 双 id（第一个过自己的、第二个过他人的）
- 方法变异：GET 拒绝试 POST/PUT/PATCH；版本降级 `/v2/` 拒绝试 `/v1/`

## 增量 3：升级链（AutoHunter）

看（读他人数据）→ 改/删（无害证法）→ 量化规模（可枚举范围 × 数据敏感度）。
报告危害写「可遍历 N 万用户的 XX 字段」，不写「存在 IDOR」。

## 判定纪律

- 双账号对照是默认证据：账号 A 的资源 id 用账号 B 的会话访问成功 = AUTHZ002 通过
- 单账号项目（无第二凭据）时：无效 id 基线 + 未登录对照，降级标注「单账号间接证据」
- 高命中参数名（order/invoice/ticket/address/message/file/report + id/no/code）命中后
  回写 `memory-global/idor-params-hit.json`（pattern_replay 通杀复用）
