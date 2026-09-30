# SQL 注入增量手册（DeepBounty 吸收版）

> 基线：Claude-BugHunter `hunt-sqli/SKILL.md`（payloads.md 已索引）。本文件只收基线之外的增量。
> 检查点映射：SQL001 报错回显 / SQL002 布尔差异 / SQL003 时间延迟 / SQL004 联合查询列数。

## 最优来源

- communitytools `skills/injection/reference/`（指纹→scenario 路由 + 四 DBMS 方言拆分）
- strix `strix/skills/vulnerabilities/sql_injection.md`（五条证据链 Validation）
- Agentic-Bug-Hunter `skills/web2-vuln-classes/SKILL.md` §SQLi（链式升级案例）

## 增量 1：指纹→scenario 路由契约（communitytools INDEX.md）

不要背 payload 清单，按**响应指纹**选场景文件，每个场景文件含该手法的完整判定契约：

| 响应指纹 | 场景文件（injection/reference/scenarios/sql/） | 一句话任务 |
|---|---|---|
| 登录表单/WHERE 拼接 | auth-bypass.md | `admin'--`、tautology |
| 可见响应需提取 | union-based.md | UNION SELECT 定列数→取数 |
| 详细 DB 报错可见 | error-based.md | CAST/CONVERT 报错带数据 |
| 布尔差异无报错 | boolean-blind.md | 布尔 oracle 逐字符 |
| 无差异无报错无 UNION | time-based-blind.md | SLEEP/pg_sleep/WAITFOR 时序 oracle |
| 异步/无带内通道 | out-of-band.md | DNS/HTTP 外带（配 deepbounty oob_client） |
| 存储后二次拼接 | second-order.md | 注册 payload + 触发第二路径 |
| 多语句支持（MSSQL/PG） | stacked-queries.md | `;` 堆叠 INSERT/UPDATE/EXEC |
| WAF 拦直白 payload | waf-bypass.md | 编码/注释/关键字嵌套（见 waf-bypass.md 专项） |
| 隐藏过滤（published=1） | where-clause-filter-bypass.md | OR-tautology 中和过滤 |
| Header 流入查询 | header-injection.md | 全自定义 Header 喷 marker |

## 增量 2：per-DBMS 指纹速查（communitytools）

| DBMS | 版本函数 | 睡眠 | 注释符 | 拼接 |
|---|---|---|---|---|
| MySQL/MariaDB | `@@version` | `SLEEP(N)` | `#` | `CONCAT()` |
| PostgreSQL | `version()` | `pg_sleep(N)` | `--` | `||` |
| MSSQL | `@@version` | `WAITFOR DELAY` | `--` | `+` |
| Oracle | `banner FROM v$version` | `dbms_pipe.receive_message` | `--` | `||`（须 `FROM dual`） |

 miner 用法：报错/回显先定 DBMS，再只打该方言的 payload，减少 WAF 暴露面。

## 增量 3：五条证据链 Validation（strix）

确认 SQLi 需同时满足：① 语法错误差异（`'` vs `''`）② tautology 差异（`OR 1=1` vs `OR 1=2`）
③ 时序可复现（≥3 次延迟均值差）④ 数据提取证明（版本/当前用户）⑤ 对照组（无害输入正常）。
缺③④时矩阵只能 found 不能提交——与 evidence_gate 的 basis 深度要求一致。

## 增量 4：NoSQL 边界提示

JSON body 且报错含 `MongoError`/`BSON` 时转 nosqli.md 手册，不要在 SQL 族上耗 bypass 次数。
