# 绕过阶段（phase-bypass，DeepBounty）

> filtered 条目的唯一出口。本阶段由 **deepbounty-bypass** 子代理承载，
> 主代理负责调度与清账。绕过族谱与纪律见其代理定义；此处为编排视角。

## 触发时机

1. **P3 中即时触发**：miner 每批总结带回 filtered 清单 → 立即调度（不等全部挖完——
   突破手法广播后能让后续 miner 直接受益）；
2. **收尾清账**：`build_bypass_list.py` 汇集全部 filtered，逐条确认已处理。

## 主代理编排

```powershell
# 汇集 filtered 台账
python .claude\skills\deepbounty\scripts\build_bypass_list.py --project <id>
```

- 按 host/防护类型分组调度 bypass 子代理（同防护的条目一批给，便于手法复用）；
- bypass 突破后：**广播确认**（shared_knowledge add-bypass 已写）→ 检查同 host 其他
  filtered 条目是否可同法突破（手法复用，一批突破）；
- bypass 全败（≥3 族）→ 条目 `bypass_final: true`，沉淀到复盘"未突破清单"。

## 出口标准

- [ ] bypass-list.json 中每条 filtered 要么转 found（有报告号），要么 bypass_final=true；
- [ ] 突破手法全部进 shared-knowledge.json（bypasses 段）；
- [ ] `evidence_gate.py` 对 bypass_final 条目校验通过（≥3 族）。

## 纪律

- **禁止**主代理口头判"绕不过"——只有 bypass 子代理实测 ≥3 族失败才算数；
- 突破后必须坐实漏洞本体（绕过≠漏洞成立），过 SRC 报告门才 found；
- 仍绕不过的条目不丢人——沉淀下来，防护变更后重测（retro 阶段标注）。
