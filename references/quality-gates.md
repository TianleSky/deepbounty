# 质量门禁 SOP(tyang-skill)

两个门禁(漏洞挖掘、威胁收敛/收尾消账)结束前都必须过门禁:**先用 Python 脚本做机器硬检查,再由 AI 做
语义复核**。有遗漏或不合规的记录必须处置完成、重新验证通过后方可流转。通过后输出对应「质量检查报告」。

> 分工原则:脚本负责**机器可判**的硬规则(格式 / 必填字段 / 枚举 / 交叉引用 / 一致性),输出
> 「必须修复」与「待复核清单」;AI 负责脚本列出的**需语义判断**的复核项。脚本 exit 0 仅代表硬检查过,
> **必须**完成 AI 复核才算门禁通过。

> Tyang 与 windftsy 的差异:**无广度建模门禁**(不走路查,接口来自导入,导入完整性由
> `import_burp → build_url_inventory` 产物与 `check_vuln_mining` 的 url-inventory 物证检查兜底)。

---

## 门禁退出态与放行判据(贯穿两门禁 · 不可空口"通过")

> 背景:曾出现门禁实为 `exit 1`(页面未解析/接口未纳入清单),却被口头记成"硬检查通过"并流转,
> 导致高价值接口漏挖。为此**门禁退出态由脚本落盘、下一阶段强制校验**,杜绝"数据改了/门禁没重跑/空口通过"。

**1|脚本落盘真实退出态(机器写,AI 不可伪造)**
每个 `check_*.py` 结束时把真实结果写入 `state.json.gates.<vuln_mining|threat_convergence>`:
`{exit, blocking_count, hard_errors[], acknowledged[], checked_at}`。**exit 语义 = blocking**(0 = 无硬错误,
或硬错误已全部**有效 acknowledged**)。

**2|放行判据 = `blocking_count == 0`**

- 硬错误能修的**先修**(补矩阵 / 补登记报告 / 补测),重跑门禁后自然消失;
- **确属客观走不通**的,在 `state.json.gates.<gate>.acknowledged` 逐条登记 `{match, reason_code, note}` 放行
  (`match`=能唯一命中该错误的子串,通常是 URL)——这是避免死锁的合法出口。未被**有效** acknowledged
  覆盖的硬错误即 `blocking`,必须清零才能流转。

**3|acknowledged 的 `reason_code`(固定集合,AI 研判标尺——要点1)**
`out_of_scope`(确认不在范围)/ `system_bug`(靶标缺陷非本方问题)/ `captcha_unbypassable`(人机校验确实绕不过)/
`precondition_unmet`(前置条件客观无法满足)/ `not_exist`(探测项确不存在 404 等)/ `accepted_residual`(承认并显式接受残余风险)。
reason_code 非法或缺 `note` 的 acknowledged **不生效**(脚本标"无效 acknowledged",对应错误仍 blocking)。
**卫生类错误(JSON/字段/枚举/矩阵缺失)不可 acknowledged,必须修**。

**4|下一阶段强制校验前置门禁(脚本读,非靠自觉)**
`check_threat_convergence.py` 开头校验 `vuln_mining`:上一门禁 `blocking_count>0` 或退出态缺失 →
本门禁直接报 `[前置门禁]` 硬错误、禁止流转。(`check_vuln_mining.py` 无前置门禁脚本,改为校验
`url-inventory.json` 非空——导入阶段物证。)

**5|质量报告须贴真实退出态、逐条列明(要点4)**
每份质量检查报告**必须粘贴门禁脚本真实的 `exit / blocking_count`**,并**逐条列出**:blocking 项如何修复、
acknowledged 项的 `reason_code + note`;`accepted_residual` 的还须进最终报告"残余缺口/未覆盖清单"。
**禁止在报告写"通过"而 `state.json` 里 `blocking_count>0`**。AI 复核须核验每条 acknowledged 理由是否成立、
reason_code 是否贴切(要点4 由 AI 按原则执行)。

---

## 漏洞挖掘质量门禁

### 第 0 步:固化必挖清单 + 并入本阶段新触达接口(脚本)

进入漏洞挖掘阶段时已用 `build_mining_scope.py` 固化必挖清单基线 `mining-scope.json`(见
[phase-vuln-mining.md](phase-vuln-mining.md)「0.固化必挖清单」)——覆盖度硬门禁只认此基线,挖掘阶段 payload 产生的
新 URL/参数(如自上传 shell 文件)不入必挖。

本阶段挖掘中常经重放打通新接口(如账号接管链里的 `reset-password`),这些成功仅落 `url_index.jsonl`。
收尾前先并入 URL 清单再校验:

```powershell
python .claude\skills\tyang-skill2\scripts\build_url_inventory.py --project {id}
```

**新触达接口是否纳入必挖**:正规业务新接口用 `build_mining_scope.py --add URLID...` 追加进必挖清单基线后
一并挖掘;确为 payload 副产物(如自上传 webshell)在 `state.json.gates.vuln_mining.acknowledged` 记
`reason_code`+`note` 放行、且**不** `--add` 进必挖清单。

### 第 1 步:硬检查(脚本)

```powershell
python .claude\skills\tyang-skill2\scripts\check_vuln_mining.py --project {id}
```

> **一致性硬错误即"打通未纳入"信号**:脚本报 `[一致性] 代理记录的 URL {id} 不在 URL 清单(请重跑 build_url_inventory.py)`
> 时,**不得跳过**——按第 0 步并入后确认该 URL 已进 `url-inventory` 并完成逐参数挖掘。

检查:`url-inventory.json` 非空(导入物证);JSON 格式/字段无缺失;`url-inventory` 与 `url_index.jsonl` 一致;**必挖清单基线
(`mining-scope.json`)内每个 URL** 两类 `*_mining_done ∈ {completed, not_applicable}`(无 `pending`),其中每个【有参数】URL 有
`vuln-matrix/{id}.json` 且**基线 `param_names`** 每个参数都有条目、`status` 合法(`found`→有已登记的 `report_id`;
`tested_not_found`/`doubtful`/`filtered`→有 `tests`+`basis`);无参数 URL 若已产出矩阵则同样校验其 `_url_level` 条目;**基线外挖掘阶段新出现的 URL/参数转软复核、不强制挖掘**
(AI 判断 payload 副产物忽略 / 正规接口 `build_mining_scope.py --add` 纳入);**通用漏洞 `filter_probe` 为结构化对象**
(`generic` 且 `tested_not_found`/`doubtful`/`filtered`:`{符号/关键字:[防护情况∈{过滤,拦截,替换,转义,放行},说明]}`,
key 疑似完整 payload 软告警不 block);**有编号要点的类型 `checkpoint_response` 逐要点应答**(KEY 命中该类型编号集、值非空,
要点见 `references/test-checkpoints.md`);`*_mining_result` 形态合法;**补测清单 `retest-list.json`(若存在,Tyang 纯导入流
通常不产生)每条已研判(`disposition` 非 `pending`)、`disposition=retest` 的须已挖掘**;**已生成报告文件
(`reports/VULN-VD-*.md`)都已登记 `vuln-reports.json`**。exit 1 逐条处置后重跑至 exit 0。

### 第 2 步:AI 复核(脚本列清单,AI 判断)

1. `filter_probe` 结构与语义专项:key 是否为单个符号/关键字(非整条 payload,重点看脚本软告警项)、防护情况(过滤/拦截/替换/转义/放行)与说明是否真实、是否覆盖该类型常用字符/关键字。
2. `checkpoint_response` 要点应答专项:有编号要点的类型是否逐要点应答(对照 `references/test-checkpoints.md`)、有无漏答关键要点、应答是否属实且与 `tests`/报告证据一致(杜绝套话)。
3. 对 `tested_not_found` / `doubtful` / `filtered` **各自抽样**复核测试结果合理性(payload、现象、判定依据是否站得住);
   重点核对状态分流:有漏洞信号但过滤/防护经真实尝试绕不过记 `filtered`(被防护),客观条件不可测记 `doubtful`(存疑),确无信号记 `tested_not_found`。
   `generic` 探到防护(过滤/拦截/替换/转义)时由测试者判断是否存在漏洞信号与绕过必要——确无信号或无绕过价值记 `tested_not_found`(`basis` 说明依据),有信号且值得绕过记 `filtered` 交收尾专项绕过;脚本对该分流列软复核抽查项、不硬拦截。
4. **基线外新增项**逐条判断:门禁软复核列出的挖掘阶段新出现 URL/参数——正规业务接口/参数则 `build_mining_scope.py --add` 纳入必挖,payload 副产物(如自上传文件、注入调试参数)忽略。
5. 所有 `notes` 特殊情况说明是否符合实际、合理。

### 输出:漏洞挖掘质量检查报告

汇总:必挖清单覆盖度、参数矩阵覆盖、报告登记数、基线外新增项处置;**门禁真实退出态**(粘贴 `state.json.gates.vuln_mining`
的 `exit`/`blocking_count` + 各 blocking 修复/各 acknowledged 的 `reason_code+note`;`accepted_residual` 项汇入
"残余缺口/未覆盖清单");AI 复核结论;遗留特殊情况说明。**`blocking_count>0` 时不得写"通过"。**
通过后更新 `state.json`:`vuln_mining=completed`,进入收尾消账/报告。

---

## 威胁收敛质量门禁(收尾消账 + 专项绕过)

Tyang 的威胁建模是挖掘期的**怀疑清单**(`threats.jsonl` 随手记),收尾时强制逐条消账,并对 `filtered`
(有漏洞信号但防护绕不过)的条目做专项绕过突破。调度方法见
[phase-threat-convergence.md](phase-threat-convergence.md)(两类任务队列,沿用 windftsy 打法)。

### 第 1 步:生成绕过台账(脚本)

```powershell
python .claude\skills\tyang-skill2\scripts\build_bypass_list.py --project {id}
```

汇集全部 `vuln-matrix` 中 `status=filtered` 的条目为 `bypass-list.json`(每条一个 `(url_id, 参数, 漏洞类型)` 绕过目标,
默认 `bypass_status=pending`),交 `pentest-bypass-miner` **按漏洞类型分组、每任务 ≤5 个同类型 URL** 专项绕过。

### 第 2 步:硬检查(脚本)

```powershell
python .claude\skills\tyang-skill2\scripts\check_threat_convergence.py --project {id}
```

检查:前置门禁 `vuln_mining` 已清零;`threats.jsonl` 无 `pending`——`confirmed` 的 `verification_report_id`
非空且在报告清单(消账到某 `VULN-VD` 报告),`excluded`/`doubtful`/`filtered` 的 `verification_detail` 有详述
(引用矩阵结论作证据);`bypass-list.json` 每条 `bypass_status` 非 `pending`、非 pending 项填 `access_note`;
`vuln-reports.json` 字段/枚举合法、`report_file` 存在、**无 `pending_review`**。exit 1 逐条处置后重跑至 exit 0。

### 第 3 步:AI 复核(脚本列清单,AI 判断)

1. **威胁消账映射专项**:每条 `confirmed`/`excluded` 是否真能在挖掘产出(`vuln-matrix`/报告)中找到对应结论,
   无缺账蒙混;缺账威胁须已调 `pentest-vuln-miner-tyang2` 补测后再消账。
2. **专项绕过复核**:逐条复核绕过台账——突破项(`filtered`→`found`)报告证据真实;仍 `filtered` 项的 `filter_probe`
   是否已扩充已试绕过族、判定成立。
3. **逐份审核收尾阶段新增报告**(补测 / 绕过突破:描述 / 复现 / 证据 / 危害),不通过则打回或拒绝,直到全部
   `approved`/`rejected`;报告被拒后若关联威胁为 `confirmed`,须反向修正该威胁状态。
4. 所有 `notes` 特殊情况说明是否符合实际、合理。

### 输出:威胁收敛质量检查报告

汇总:威胁确认/排除/存疑/被防护分布、绕过突破/仍被防护数、报告通过/拒绝数;**门禁真实退出态**(粘贴
`state.json.gates.threat_convergence` 的 `exit`/`blocking_count` + 各 blocking 修复/各 acknowledged 的
`reason_code+note`;`accepted_residual` 项汇入"残余缺口/未覆盖清单");AI 复核结论;遗留特殊情况说明。
**`blocking_count>0` 时不得写"通过"。** 通过后更新 `state.json`:`reporting=completed`,
并将 `index.json` 对应项 `status` 视情置 `completed`。
