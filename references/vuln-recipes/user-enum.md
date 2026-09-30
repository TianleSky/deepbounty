# 用户枚举增量手册（DeepBounty 吸收版）

> 基线：Claude-BugHunter `hunt-auth-bypass/SKILL.md` 相关章节。检查点映射：ENUM001 响应差异 / ENUM002 时序或侧信道差异。

## 最优来源

- communitytools（存在性侧信道 oracle + 时序/锁定方法论）
- BountyGrimoire `.claude/skills/find-enumerable`（顺序 ID/Base64 GID/时序攻击）
- AutoHunter `prompts.py`（**拒收口径**：单独枚举通常不报——防浪费）

## 增量 1：存在性 oracle 全清单（communitytools）

按优先级测：
1. **错误校验顺序**：先校验用户名存在性再校验密码 → 存在/不存在返回不同错误文案或字段
2. **响应差异**：状态码/响应体长度/错误码（`USER_NOT_FOUND` vs `WRONG_PASSWORD`）
3. **时序**：存在用户走密码哈希（慢）vs 不存在直接返回（快）——≥50 次采样取中位数差
4. **锁定策略**：存在用户 N 次失败锁定，不存在用户不锁定
5. **注册/找回密码**：「该手机号已注册」/「用户不存在」直白提示
6. **验证码触发差异**：存在用户触发图形码，不存在不触发

## 增量 2：ID 可枚举性（BountyGrimoire）

- 顺序数字 ID：差值采样确认连续性
- Base64 编码 GID：解码看内部结构（`gid://shopify/User/1234` 式）
- UUID v1：时间戳+MAC 可预测；v4 不可枚举（标注排除）

## 增量 3：拒收口径（AutoHunter，直接移植）

- **单独用户枚举在多数 SRC 属低危/不收**——必须链到实际危害才报：
  枚举 → 定向爆破/撞库 → ATO；枚举 → 精准钓鱼；枚举 → 配合短信轰炸
- 挖掘时仍记录矩阵（status=open），但标「需链式升级」，不单独进验证队列

## 判定纪律

- ENUM001 差异必须是**稳定二分类**（≥10 个已知存在 + ≥10 个随机不存在样本，准确率 100%）
- 时序类需排除网络抖动：跨时段复测两轮
