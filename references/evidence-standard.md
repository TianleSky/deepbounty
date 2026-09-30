# 举证标准（evidence standard，DeepBounty）

> 各终态的举证要求。`evidence_gate.py` 机读硬校验 + AI 复核双轨。
> 修 tyang-skill2 "20% tested_not_found 描述<50字符、filtered 举证无人看"。

## 状态总览

| 状态 | 语义 | 机读硬校验 | AI 复核 |
|---|---|---|---|
| found | 漏洞坐实过 SRC 门 | 报告存在+零脱敏+≥2000字节+含请求/响应段+非 C 类标题+report_id 已登记+cred_id 可解析 | 证据链真实性、L3 深度 |
| filtered | 有信号+有防护 | filter_probe 有防护命中（无命中=自相矛盾硬错误） | 防护判定是否属实 |
| filtered+bypass_final | ≥3 族绕过全败 | bypass_attempts ≥3 族（不足硬错误） | 各族尝试真实性 |
| tested_not_found | 确无信号 | basis ≥50 字符 + probe_count ≥3 + tests 非空 + filter_probe **全放行**（有防护命中却判 tnf = check_vuln_mining 硬错误） | 判定依据抽样 |
| doubtful | 客观不可测 | death_cause 必填（∈ DEATH_CAUSE 枚举） | 是否滥用兜底 |
| blocked | 前置缺失 | （任务树侧）death_cause/notes 说明 | 前置是否真不可解 |
| not_applicable | 不适用 | basis 简述 | 适用性判断 |

## 通用要求（所有终态）

- `cred_id` 强制：本条测试用的身份（未授权面填 `none`）；必须能在 cred/sessions.json
  解析（evidence_gate 校验，追溯率 ≥95%）；
- `probe_count` 强制：本条发出的探测请求数；
- `tests`：每次测试 `{payload, response_essentials}`——响应要点不是全文（全文在代理日志/报告）；
- 重放走代理留痕，证据以 `proxy-logs/requests/` 落盘报文为准。

## tested_not_found 的 basis 怎么写（≥50 字符）

坏例子（门禁硬拦）：`"测试无注入"`、`"payload 均无效"`。

好例子：
```
"id 参数数字型。测 '、\"、1'and'1'='1、1 and 1=2 等 12 发：响应均 200 且长度一致(±3%)，
无报错无回显差异；filter_probe 全放行（无防护）；order by 1-30 列数无差异。
判无注入依据：输入不改变响应语义。"
```

要素：测了什么（payload 族）+ 发了多少 + 观察到什么 + 为什么判无。

## filtered 的 filter_probe 怎么写

```json
"filter_probe": {
  "'": ["拦截", "含单引号即 403，WAF 页"],
  "and": ["过滤", "关键字被剔除后正常返回"],
  "/**/": ["放行", "原样通过"],
  "空格": ["替换", "被替换为空串"]
}
```

key = 单个符号/关键字（非整条 payload）；value = [防护情况∈{过滤,拦截,替换,转义,放行}, 说明]。
**全放行才准 tested_not_found；任一非放行 = filtered 交 bypass。**

## bypass_attempts 怎么记

```json
"bypass_attempts": [
  {"family": "编码族", "payload": "%27%20and%20...", "result": "仍 403"},
  {"family": "注释族", "payload": "'/**/and/**/...", "result": "绕过过滤但无注入信号"},
  {"family": "协议族", "payload": "Content-Type 切换 json", "result": "参数不解析"}
]
```

## doubtful 的 death_cause

| 值 | 场景 |
|---|---|
| network_error | 持续超时/连接拒绝 |
| guard_block | 防护拦截且 bypass 未涉及/未成功 |
| param_ineffective | 参数改与不改响应完全一致 |
| business_reject | 业务校验拒绝（签名/前置状态） |
| budget_exhausted | 预算帽耗尽 |
| unknown | 其他（须详述） |
