# P0 导入阶段（DeepBounty）

> 目标：把 SRC 资产库中某 project 的已入库接口完整拉到本地，固化必挖基线。
> 不做侦察——接口即契约（借 Strix 契约驱动：入库接口逐个声明逐个测）。

## 输入

- 用户给出：项目标识（资产库 `project` 字段值，如 `haodf-src`）、工作守则（可选）。
- **无限制原则**：不问安全边界——无 scope/exclude/security_level 概念，资产库项目即授权范围，全接口全操作放开。

## 步骤

### 1. 初始化项目

```powershell
python .claude\skills\deepbounty\scripts\init_project.py --project <id> --data-root pentest-data
```

- 建目录（含 cred/ memory/ oob/）；写 state.json（phase_status: import/credentials/task_tree/vuln_mining/validation/retro）；
- config.json：`scope`/`exclude` 默认空（=不限制，无限制原则）/ `work_guidelines`（用户有补充守则才写）；
- config 含 `oob_provider`（interactsh 公共服）/ `leaf_budget`（max_requests=60, max_rounds=12）。

### 2. 从资产库拉接口

```powershell
python .claude\skills\deepbounty\scripts\import_srcdb.py --project <id> --project-name <资产库project名>
```

- 按 project 字段增量拉取 endpoint 表（host/kind/method/path/request_url/request_headers/request_body/response_*）；
- 增量：已入库的 URL 不重复拉（断点续跑）。

### 3. 建 URL 清单与必挖基线

```powershell
python .claude\skills\deepbounty\scripts\build_url_inventory.py --project <id>
python .claude\skills\deepbounty\scripts\build_mining_scope.py --project <id>
```

- url-inventory.json：URLID/分类（page/api/static/other）/参数名；
- mining-scope.json：**必挖基线固化**——后续覆盖度硬门禁只认此基线；
- 无限制原则：接口全量纳入，无 scope/exclude 剔除。

### 4. 提取 URL 上下文（可延后到挖掘前）

```powershell
python .claude\skills\deepbounty\scripts\extract_url_context.py --project <id>
```

## 出口门禁（全满足才进 P1）

- [ ] url-inventory.json 非空且与资产库 project 接口数一致（抽样核对）；
- [ ] mining-scope.json 已固化；
- [ ] state.json.phase_status.import = done。

## 常见坑

- 资产库 project 名与用户口头项目名不一致 → 先查库列出候选 project 让用户选；
- 接口量大（>5000）→ 按 host 分批建树挖掘，mining-scope 仍一次固化。
