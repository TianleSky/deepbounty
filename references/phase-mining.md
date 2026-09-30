# P2 任务树 + P3 深度挖掘阶段（DeepBounty）

> P2 把"要测什么"结构化成任务树；P3 批量调度 miner 把每个叶子推到终态。
> 本阶段是 DeepBounty 第二核心——**每个参数都有交代，每个防护都被认真对待**。

## P2 任务树构建

### 1. 端点能力画像 + 兼容矩阵

```powershell
python .claude\skills\deepbounty\scripts\capability_matrix.py --project <id>
```

产出 `endpoint-capabilities.json`：每个端点的方法/参数位置/Content-Type/has_upload/has_xml/
has_jwt/auth_seen 画像 + 适用漏洞类白名单（规则见 [capability-matrix.md](capability-matrix.md)）。
**杜绝无意义组合**（对无参 GET 测 SQLi、对 JSON 接口测 XXE 不会出现在任务树里）。

### 2. 隐藏参数发现（重点接口）

```powershell
python .claude\skills\deepbounty\scripts\param_discover.py --project <id> --url-id URL00012
```

Arjun 式爆破（内置字典 + 金丝雀值 + 基线对比）；新参数并入 params/{uid}.json 与清单。
优先对：业务核心接口（order/pay/user）、响应丰富的接口、历史命中模式的参数名接口。

### 3. 记忆预热（强制）

```powershell
python .claude\skills\deepbounty\scripts\shared_knowledge.py --project <id> import-global
python .claude\skills\deepbounty\scripts\pattern_replay.py --project <id> stats
```

读 `memory-global/`：vuln-patterns（同类参数优先测历史命中模式）、false-positives
（误报特征降权）、waf-bypass（已知手法）、lessons-learned。

### 4. 建树

```powershell
python .claude\skills\deepbounty\scripts\task_tree.py --project <id> build
python .claude\skills\deepbounty\scripts\task_tree.py --project <id> status
```

四级任务树：Project→Host→Endpoint→(Param×VulnClass) 叶子；
状态机 `pending→probing→signal→exploiting→confirmed|filtered|exhausted|blocked`；
coverage.json `authz_blocked=true` 的 host，AUTHZ/IDOR 叶子直接 blocked。

## P3 深度挖掘

### 1. 批量调度 miner

```powershell
python .claude\skills\deepbounty\scripts\task_tree.py --project <id> next 10
```

按 untested-first 取批（≤10 URL），调度 **deepbounty-miner** 子代理。
miner 契约（其定义即权威）：渐进探测（低强度→有信号升级）、预算帽、死因分类、
OOB 强制、checkpoint 全覆盖、情报回写。

### 2. filtered 即时绕过（不等收尾）

miner 总结中的 filtered 清单 → **立即**调度 **deepbounty-bypass**：

- ≥3 族绕过真实尝试；突破→坐实 found + `shared_knowledge.py add-bypass` 广播；
- 全败→`bypass_final: true`（不足 3 族 evidence_gate 硬拦）。

### 3. 越权专项

host 有双账号（coverage `authz_blocked=false`）→ 调度 **deepbounty-authz**：
`authz_probe.py` 基线 + AUTHZ001-004 坐实（真双账号 diff、水平 ID 枚举）。

### 4. 凭据异常救援

miner/authz 报告 401/失效 → 调度 **deepbounty-cred-steward** 现场救援，
救援成功前暂停该 host 挖掘（失效身份产出的结论无效）。

### 5. 每批收尾

```powershell
python .claude\skills\deepbounty\scripts\task_tree.py --project <id> sync
```

矩阵 → 任务树回同步（confirmed 不降级）。然后取下一批。

### 6. 阶段出口：总门禁

```powershell
python .claude\skills\deepbounty\scripts\check_mining.py --project <id>
```

六道检查：cred 前置 / check_vuln_mining / evidence_gate / checkpoint_gate /
任务树一致 / 深度指标（凭据追溯率≥95%、filtered 占比、平均探测深度）。
exit 0 才进 P4。客观走不通 → `state.json.gates.check_mining.acknowledged` 逐条登记。

## 状态分流纪律（矿工与主代理共同遵守）

| 情况 | 状态 | 举证 |
|---|---|---|
| 漏洞坐实过 SRC 门 | found | 报告零脱敏全文 + cred_id |
| 有信号+有防护 | filtered | filter_probe 防护命中；交 bypass |
| 防护≥3族绕不过 | filtered+bypass_final | bypass_attempts 每族证据 |
| 确无信号 | tested_not_found | filter_probe 全放行 + probe_count≥3 + basis≥50字符 |
| 客观不可测 | doubtful | death_cause + 详细说明 |
| 无双账号测越权 | blocked | notes 写明前置缺失 |
