# NoSQL 注入增量手册（DeepBounty 吸收版）

> 基线：Claude-BugHunter `hunt-nosqli/SKILL.md`。检查点映射：NOSQLI001 操作符注入 / NOSQLI002 布尔或时序差异。

## 最优来源

- communitytools `skills/injection/reference/scenarios/nosql/`（Mongo 五手法 + Redis/Cassandra/ES）
- strix `strix/skills/vulnerabilities/nosql_injection.md`（7 种后端 + GraphQL 变量注入）
- Agentic-Bug-Hunter `bughunter/tools/nosqli_scanner.py`（差分/时序判定脚本，可直接跑）

## 增量 1：MongoDB 五手法场景族（communitytools）

| 指纹 | 场景文件 | 核心手法 |
|---|---|---|
| JSON body `db.find(req.body)` | mongo-operator-injection.md | `{"$ne":null}`、`{"$gt":""}`、`{"$regex":"^a"}` 认证绕过 |
| `$where` JS 谓词 | mongo-where-jsinjection.md | `'||'a'=='b` 布尔盲注逐字符提取 |
| 字符串拼接进查询 | mongo-syntax-injection.md | tautology 镜像 SQLi 的 `' OR '1'='1` |
| 聚合管道 | mongo-aggregation-pipeline.md | `$lookup` 跨集合、`$function` 执行 JS |
| URL 编码 `[bracket]` 表单解析 | mongo-type-confusion.md | `password[$ne]=` → `{$ne:""}`（Express qs 解析器） |

## 增量 2：其他后端（strix 最全）

- **Redis**：SSRF+gopher 打 Redis（communitytools redis-ssrf-gopher.md：Gopherus→webshell/SSH key/cron）
- **Elasticsearch**：内联 script 代理——原始 `'` 在 quote-strip 后存活 → Rhino 逃逸（`'x'||true||''`）；ES ≤5.x scripting RCE
- **Cassandra**：9042 默认凭据 + Java UDF RCE
- **DynamoDB/CouchDB/Neo4j**：strix 各有专节（比较操作符/视图注入/Cypher 注入）

## 增量 3：GraphQL 变量注入（strix 独家）

GraphQL 变量槽位类型为 JSON 时，变量值直接进 NoSQL 查询：
`{"username":{"$gt":""},"password":{"$gt":""}}` 作为 variables 传入，绕过对 query 字符串的过滤。

## 判定纪律

- 差分判定：注入组 vs 对照组响应体差异必须稳定复现（nosqli_scanner.py 的 diff 模式）
- 时序判定：Mongo `$where` 睡眠 `sleep(5000)||true` 需 ≥3 次均值差 ≥4s
- 认证绕过类必须落到「进入 authenticated 界面」截图/响应，仅 200 不算（对齐 evidence_gate）
