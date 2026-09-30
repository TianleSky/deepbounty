# 优惠/积分/抽奖增量手册（DeepBounty 吸收版）

> 基线：Claude-BugHunter `hunt-business-logic/SKILL.md`。检查点映射：PRIZE001 复用/超发/篡改证明。

## 最优来源

- communitytools `scenarios/`（`coupon-stacking.md`/`gift-card-loop.md`/`price-manipulation.md`）
- pentest-agents `skills/hunt-business-logic/SKILL.md`（906 行：Coupon 堆叠/过期复用/竞态领取 + 美元量化纪律）
- VEGA `agents/vega-logic.md`（支付状态机建模，中国电商场景）

## 增量 1：支付状态机建模（VEGA，方法论核心）

把业务画成状态机：节点=订单状态（待支付/已支付/已发货/已退款/已完成），边=操作（支付/取消/退款/确认收货）。
漏洞=**非法边**或**边的重入**：
- 并发用券：同一券在两笔并发订单同时核销（交叉 RACE 类）
- 重复退款：退款边可重入（交叉 REPLAY 类）
- 价格篡改：状态转移间价格参数可改（下单价 vs 支付价分离）
- 状态回滚：已发货→取消订单→券退回但货不退

## 增量 2：场景 checklist（communitytools + pentest-agents 合订）

- **Coupon 堆叠**：互斥券同单叠加、同券多次应用、券+积分+满减三重叠加超限
- **过期/已用券复用**：改券状态字段、时区边界（过期瞬间并发）、领取接口重放
- **gift-card-loop**：礼品卡买礼品卡自充值放大、余额转移竞态
- **price-manipulation**：负数数量、小数精度截断（0.001 单价）、货币单位混淆（分/元）、
  运费篡改、SKU 替换（低价 SKU 高价商品）
- **抽奖**：概率参数篡改、并发抽奖超发、奖品库存负数、抽奖资格伪造

## 增量 3：量化纪律（pentest-agents）

危害一律金额化：「单次调用获利 X 元 × 可并发 N 次 × 每日上限 M」= 日损失上限。
无金额化能力的逻辑洞（如仅绕过签到限制）降级为低危。

## 判定纪律

- PRIZE001 通过标准：实际完成一次受益操作（券核销成功/积分到账/奖品超发），
  且用自有账号闭环（不消耗他人资产）——对齐 authz.md 无害证法
- 涉及真实支付的：用最小面额（0.01 元）测试单闭环，禁止大额
