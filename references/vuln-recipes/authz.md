# 越权（BOLA/BFLA）增量手册（DeepBounty 吸收版）

> 基线：Claude-BugHunter `hunt-idor/SKILL.md` + deepbounty `authz_probe.py`（双账号 diff 已落地）。
> 检查点映射：AUTHZ001 未授权访问 / AUTHZ002 水平越权 / AUTHZ003 垂直越权 / AUTHZ004 写操作无害证明。

## 最优来源

- AutoHunter `app/agents/write_proof.py`（**无害写证法五分类**，独家，直接移植判定逻辑）
- strix `broken_function_level_authorization.md`（Actor×Action 矩阵 + 动词漂移）
- communitytools `scenarios/access-control/`（method/header/referer/多步/mass-assignment 路由）

## 增量 1：无害写证法五分类（AutoHunter，AUTHZ004 的直接实现）

写/删/改越权举证的死结：不许改真实数据 vs 只返回 200 不算洞。解法按强度分五类：

| 类别 | 强度 | 做法 |
|---|---|---|
| sentinel 哨兵闭环 | 强 | 自建带唯一标识对象（`SRC_TEST_<rand>`），增→改→删只碰自己这条，旁路 GET/列表回读 before→after |
| authz_diff 鉴权对照 | 强 | 未登录/无 token 应 401/403，带低权登录态变 200/授权通过——denied+allowed+contrast 三要素齐备 |
| idempotent 幂等回写 | 强 | 只能碰已有对象时写回**原值**，看 affectedRows≥1 或授权通过且值未变 |
| side_read 旁路回读 | 强 | 写操作后经另一接口回读确认状态变化（before/after 对比） |
| weak | 拦截 | 只有成功文案或 `data:0`/「对象不存在」——**不算证据**，必须补无害证法 |

配套纪律（should_skip_live_replay 移植）：已取证的写/删洞**禁止现场复放** PoC
（`drop table`/`rm -rf`/sqlmap `--dump` 类一律禁），防止复现变破坏。

## 增量 2：Actor×Action 矩阵（strix BFLA）

建模：行=角色（匿名/普通/VIP/管理员/租户A/租户B），列=动作（读/写/删/导出/审批/配置）。
每个格子标 允许/拒绝/未测。垂直越权优先测：**动词漂移**（GET→POST→PUT→DELETE→PATCH）、
功能开关参数（`?admin=true`、`?debug=1`）、内部接口路径猜测（`/internal/`、`/manage/`）。

## 增量 3：access-control 路由场景（communitytools）

- method override：`X-HTTP-Method-Override: DELETE`
- header 伪装：`X-Original-URL`/`X-Rewrite-URL` 指向管理路径（前端路由放行、后端真执行）
- referer 校验绕过：伪造 `Referer: /admin/` 满足「从管理页发起」校验
- 多步流程跳步：步骤 2 直接提交步骤 4 的接口
- mass-assignment：注册/更新时塞 `role`/`isAdmin`/`balance` 字段

## 判定纪律

- AUTHZ004 只认五分类中的强类；weak 类打回 miner 补证（与 evidence_gate 联动）
- 双账号 diff（authz_probe.py 产出）是 AUTHZ002/003 的默认证据形态
