# 竞态增量手册（DeepBounty 吸收版）

> 基线：Claude-BugHunter `hunt-race-condition/SKILL.md`（HTTP/2 单包 + Turbo Intruder 已全）。
> 检查点映射：RACE001 并发超发证明 / RACE002 双花或状态错乱 / RACE003 串行对照。

## 最优来源

- communitytools `scenarios/race-conditions/`（12 场景 + **PREDICT/PROBE/PROVE 方法论**）
- Claude-BugHunter `hunt-race-condition`（单包攻击工程化，基线已强）
- strix `race_conditions.md`（「串行拒绝、并发成功」Validation 标准）

## 增量 1：PREDICT/PROBE/PROVE 三阶段（communitytools 方法论）

- **PREDICT**：读业务流程找「检查与使用分离」（TOCTOU）点——余额检查→扣款、库存检查→下单、
  券状态检查→核销、验证码校验→消费。凡是「先 SELECT 判断再 UPDATE」的代码模式都可疑
- **PROBE**：小并发（5-10 请求）探时间窗——响应时间差 >50ms 的接口窗口更大；
  观察是否有锁表现（并发时部分请求变慢/报错）
- **PROVE**：精准并发（HTTP/2 单包/last-byte sync）打满窗口，收集成功响应数

## 增量 2：12 场景清单（communitytools）

限额绕过（提现/转账/领券）、库存超卖、双花、投票/点赞刷量、注册用户名抢占、
邮箱/手机换绑竞态、密码重置 token 竞用、OAuth state 竞用、2FA 验证码竞用、
文件上传同名覆盖、优惠券并发核销、退款并发。

## 增量 3：Validation 标准（strix）

**「串行拒绝、并发成功」** 是黄金判定：
- 对照组：串行发 N 次同请求，只有 1 次成功（业务限制生效）
- 实验组：并发发 N 次同请求，>1 次成功（限制被绕过）
- 两组结果同报告，缺对照组不算 RACE001 通过（与 evidence_gate 对照组要求一致）

## 工程要点（基线已有，强调）

- HTTP/2 单包攻击优先于多线程（消除网络抖动）；HTTP/1.1 用 last-byte sync
- 并发数从 5 起步逐步加到 30；>30 无效果多半有锁，换场景不硬刚
- 所有竞态测试用**自有账号/自有资源**闭环（对齐无害证法）
