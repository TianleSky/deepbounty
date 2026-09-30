# P4 盲验证阶段（DeepBounty）

> 目标：所有 found 条目经独立复现确认，把误报拦在报告登记之前。
> 借 communitytools 盲审 + BountyGrimoire curl 复现：validator 只看证据不看攻击链。

## 步骤

### 1. 汇集待验证清单

扫 `vuln-matrix/` 全部 `status=found` 且未 `validated: true` 的条目。

### 2. 调度 deepbounty-validator

分批给（每批 ≤10 条）。**只给**：url-id + 参数 + 漏洞类型 + 矩阵条目位置。
**不给**：miner 的分析思路、payload 推导过程（防先入为主）。

validator 做（其定义为权威）：
1. 证据完整性预审（零脱敏/cred_id/checkpoint 全覆盖）；
2. 独立复现（自己的 curl/python，按 cred_id 带凭据，走代理留痕）；
3. 7 问门；
4. SRC 报告门复核。

### 3. 处理验证结论（validation/*.json）

| verdict | 动作 |
|---|---|
| confirmed | 矩阵条目加 `validated: true`；报告可登记 |
| rejected | 矩阵打回 doubtful（basis 追加打回原因）；报告标题加【已拒绝】；**误报特征交复盘沉淀** |
| blocked（凭据失效） | 调度 cred-steward 救援后重新验证 |

### 4. 报告登记

```powershell
python .claude\skills\deepbounty\scripts\register_report.py --project <id> --vuln-id <VULN-VD-xxx> ...
```

只登记 validated 的报告。每份报告必须含「SRC提交稿」（标题、漏洞 URL、浏览器逐步复现流程、完整请求包、完整响应包、修复建议），`evidence_gate.py` 缺节即硬错误。`check_vuln_mining.py` 硬校验：报告文件 ↔ 登记清单一致。

### 5. 飞书发布（主代理自己执行，不计入出口门禁）

出口门禁核对之后，主代理自己运行下面的命令，不要把命令交给用户。发布技能的最终报告：`review_status=approved`，或仍为 `pending_review` 但盲验证 `verdict=confirmed`。`rejected` 不发。没有这类报告就跳过，不要空跑。

```powershell
python .claude\skills\deepbounty\scripts\publish_feishu.py --project <id>
```

脚本把该报告 Markdown 和其中能解析到的本地截图发布为飞书云文档，并在现有漏洞多维表格按 `VULN-VD号` 写入或更新「飞书文档」列。飞书未登录、缺图或接口失败只打印，不改 `review_status`，不阻断本阶段出口，也不阻断 P5。命令、表和幂等规则见 [feishu-publish.md](feishu-publish.md)。

## 出口门禁

- [ ] found 条目全部 validated 或已打回（无悬空 found）；
- [ ] vuln-reports.json 登记齐全；
- [ ] 打回条目的误报特征已记录（交 P5 误报库）。

## 纪律

- validator 不替 miner 补洞——复现失败就是失败；
- 「差不多能复现」= 失败；
- 主代理不得因"报告都写了"而施压放行——打回是常态，误报入库是财富。
