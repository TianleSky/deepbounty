# P5 通杀 + 复盘阶段（DeepBounty）

> 目标：一个洞变成一片洞（通杀），一个项目打完系统变强（复盘）。
> 借 AutoHunter 通杀复用 + VEGA 复盘进化 + PentAGI Smart Memory。

## 步骤

### 1. 通杀复用（pattern_replay）

对每个 validated 的 found 条目提取模式：

```powershell
python .claude\skills\deepbounty\scripts\pattern_replay.py --project <id> extract `
  --url-id <URLID> --param <参数> --vuln-type <类型> `
  --payload <最终生效payload> --signal-type <keyword|status|time> --signal-value <信号> `
  --report-id <VULN-VD号>
python .claude\skills\deepbounty\scripts\pattern_replay.py --project <id> candidates --pattern-id <PAT-xxx>
python .claude\skills\deepbounty\scripts\pattern_replay.py --project <id> replay --pattern-id <PAT-xxx> [--dry-run]
```

- 候选 = 同项目同指纹（同漏洞类适用 + 同名参数）且未确认的接口；
- replay 命中项 → **回调 miner 坐实**（通杀只给信号，不直接入账）；
- 坐实出新洞 → 回到 P3/P4 流程（新 found 又可再提取模式，滚雪球）。

### 2. 复盘沉淀（调度 deepbounty-retro）

```powershell
python .claude\skills\deepbounty\scripts\shared_knowledge.py --project <id> export-global
python .claude\skills\deepbounty\scripts\pattern_replay.py --project <id> stats
```

retro 子代理（其定义为权威）产出：
- `memory-global/vuln-patterns.json`：通杀模式（extract 自动沉淀）；
- `memory-global/waf-bypass.json`：WAF 指纹+绕过手法；
- `memory-global/idor-params-hit.json`：参数命中统计；
- `memory-global/false-positives.json`：误报特征（validator 打回 + SRC 拒收）；
- `memory-global/lessons-learned.md`：三大教训+流程改进；
- `memory/retro-<date>.md`：项目复盘报告（战果/深度指标/未突破清单）。

### 3. 状态收尾

- state.json.phase_status.retro = done；
- 未突破清单（filtered+bypass_final）标注"防护变更后值得重测"。

## 出口门禁

- [ ] memory-global 四个 JSON 已更新（mtime 晚于项目开始）；
- [ ] 复盘报告落盘；
- [ ] 通杀命中项已全部回调坐实或明确放弃（notes 说明）。

## 下一个项目受益点

新项目 P2 记忆预热时自动读本阶段沉淀：同指纹模式优先测、误报特征降权、
已知 WAF 手法直接复用——**每个项目打完，下个项目的起点更高**。
