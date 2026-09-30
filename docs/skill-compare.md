# 14 家 SKILL 分漏洞类型对标矩阵（DeepBounty 学习选型）

> 生成于 2026-09-29。以 deepbounty 兼容矩阵的 21 个漏洞类为轴，对 14 家公开项目逐类评分。
> 评分：0=无 · 1=仅提及 · 2=有 payload 表/checklist · 3=系统 payload 表+判定逻辑+实战案例/脚本。
> 仓库本地路径：`D:\Tools\AI\AIsrc\SKILL\ref-repos\<名>`；Claude-BugHunter 为本地基线
> `C:\Users\Administrator\.claude\plugins\cache\elementalsouls\claude-bughunter\2.1.0\skills\`。
> pentagi / cai 均已到货补评：pentagi=Go 编排平台（flows/docker/searchers/browser 工具链）、
> cai=Python 编排/benchmark 框架（caibench/fluency），均无分漏洞类型 payload 库，21 类全部 0 分，
> 定位同 PentestGPT——不改变任何排名。

## 一句话结论

- **分漏洞类型最详细**：communitytools（scenario 族最系统）、pentest-agents（hunt-* 长文最深）、strix（skill 模板最规范）、Agentic-Bug-Hunter（教材+可执行扫描器）
- **WAF 绕过最值得学**：pentest-agents（7 级绕过阶梯+waf-profiler）、communitytools（边缘绕过+反 bot）、Agentic-Bug-Hunter（waf_encoder/multipart_mutator 工具化）、Claude-BugHunter（arsenal 评估顺序）
- **判定/取证纪律最值得学**：AutoHunter（无害证法+EduSRC 收洞口径）、strix（counterevidence 三态）、Argus（误报治理判定）
- **业务逻辑（国内 SRC 高频）**：VEGA（状态机建模+中国场景）、communitytools（竞态/优惠券场景族）、pentest-agents（hunt-business-logic）
- **可忽略**：PentestGPT（纯编排，漏洞知识≈0）

## 总评分矩阵（21 类 × 11 家有效来源）

| 漏洞类 | Argus | VEGA | AutoHunter | BountyGrimoire | Agentic-BH | communitytools | pentest-ai-agents | pentest-agents | PentestGPT | strix | Claude-BugHunter |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| SQL注入 | 3 | 1 | 2 | 3 | 3 | **3** | 3 | 2 | 0 | 3 | 3 |
| NoSQL注入 | 1 | 0 | 1 | 0 | 3 | **3** | 3 | 2 | 0 | 3 | 2 |
| XSS | 3 | 1 | 2 | 3 | 3 | 3 | 2 | **3** | 0 | 3 | 3 |
| 命令注入 | 3 | 1 | 2 | 3 | 2 | 3 | 3 | **3** | 1 | 3 | 3 |
| SSRF | 3 | 3 | 2 | 3 | **3** | 3 | 2 | 2 | 0 | 3 | 3 |
| XXE | 1 | 0 | 1 | **3** | 3 | 2 | 1 | 2 | 0 | 3 | 3 |
| 路径穿越 | 3 | 2 | 2 | 2 | 3 | **3** | 2 | 2 | 0 | 3 | 3 |
| 文件上传 | 1 | 2 | 2 | 3 | **3** | 3 | 2 | 2 | 0 | 3 | 2 |
| SSTI | 3 | 0 | 2 | 3 | 3 | 3 | 2 | 3 | 1 | **3** | 2 |
| ELI | 1 | 1 | 1 | 1 | 2 | 2 | 0 | 2 | 0 | **2** | 2 |
| JWT | 2 | 2 | 2 | 1 | 3 | **3** | 3 | 3 | 0 | 3 | 2 |
| 用户枚举 | 0 | 2 | 1 | 3 | 2 | **3** | 2 | 2 | 0 | 2 | 2 |
| 越权 | 3 | 3 | **3** | 3 | 3 | 3 | 3 | 2 | 1 | 3 | 2 |
| IDOR | 3 | 3 | 3 | 3 | 3 | 3 | 3 | **3** | 0 | 3 | 3 |
| 优惠/积分/抽奖 | 0 | 3 | 1 | 2 | 2 | **3** | 3 | 3 | 0 | 2 | 3 |
| 竞态 | 0 | 3 | 1 | 3 | 3 | **3** | 3 | 3 | 0 | 3 | 3 |
| 重放 | 0 | 3 | 1 | 2 | 2 | **3** | 2 | 2 | 0 | 2 | 3 |
| 验证码/短信绕过 | 0 | 3 | 2 | 3 | 2 | **3** | 2 | 2 | 0 | 1 | 2 |
| 开放重定向 | 2 | 1 | 1 | **3** | 2 | 1 | 2 | 2 | 0 | 3 | 2 |
| CORS | 0 | 0 | 1 | 1 | **3** | 3 | 2 | 2 | 0 | 1 | 3 |
| 敏感信息泄露 | 3 | **3** | 3 | 3 | 3 | 3 | 2 | 3 | 0 | 3 | 3 |
| **WAF 绕过丰富度** | 2 | 2 | 2 | 1 | **3** | **3** | 2 | **3** | 0 | 2 | **3** |

## 每类最优来源与可吸收点

### 1. SQL注入 → communitytools + strix + Claude-BugHunter
- communitytools `skills/injection/reference/scenarios/sql/`：四 DBMS 方言拆分 + waf-bypass/where-filter/second-order 场景族，指纹→scenario 路由
- strix `vulnerabilities/sql_injection.md`：Validation 五条证据链
- Claude-BugHunter `hunt-sqli`：WAF 绕过族（注释/编码/运算符/Header/Chunked）+ Gate0
- Argus 补充：基线防误报判定（`actions.py` 报错+时间判定）

### 2. NoSQL注入 → communitytools + strix + Agentic-Bug-Hunter
- communitytools `scenarios/nosql/`：Mongo 五手法（operator/where/syntax/aggregation/type-confusion）+ Redis/Cassandra/ES
- strix `nosql_injection.md`：7 种后端 + GraphQL 变量注入
- Agentic-Bug-Hunter `bughunter/tools/nosqli_scanner.py`：差分/时序判定脚本

### 3. XSS → pentest-agents + communitytools + Claude-BugHunter
- pentest-agents `skills/hunt-xss/SKILL.md`（789 行）：CVE 元分析 + mXSS/DOMPurify/postMessage 判定树 + 检测旋转阶梯
- communitytools `scenarios/xss/`：11 个影响链场景（cookie 窃取→内网扫描），"已有 XSS 后如何证明危害"
- Claude-BugHunter `hunt-xss`：CSP/Angular CSTI 硬变体 + OOB 盲 XSS 门
- Argus 补充：转义后假反射排除判定

### 4. 命令注入 → strix + pentest-agents + Claude-BugHunter
- strix `rce.md` + `argument_injection.md`：argv/option smuggling/`@response-file`（独家硬核）
- pentest-agents `hunt-rce`（925 行）：无空格绕过/参数注入 + CVE 实战链
- Claude-BugHunter `hunt-rce`：`$IFS`/关键词混淆 + OOB 确认

### 5. SSRF → Agentic-Bug-Hunter + Claude-BugHunter + communitytools
- Agentic-Bug-Hunter `web2-vuln-classes` §4：11 种 IP bypass +「仅 DNS 回调=不足以提交」triage 硬规则
- Claude-BugHunter `hunt-ssrf`：黑名单绕过最全（IPv6/进制/DNS rebinding/解析歧义）+ OOB-Or-It-Didn't-Happen
- communitytools `scenarios/ssrf/`：header-name 打 Redis、UTF-8 二进制丢失等稀缺边角
- VEGA 补充：DNSLOG PoC 模板（中国 SRC 风格）

### 6. XXE → BountyGrimoire + Agentic-Bug-Hunter + strix
- BountyGrimoire `find-xxe`：ASP.NET/SXMP/WAV 上传链/WP 媒体库实战链（真实披露风格）
- Agentic-Bug-Hunter：Blind OOB-DTD + 上传载体 + SAML XXE + OOB 绑定
- strix `xxe.md`：XInclude/XSLT/`document()` + OOXML 上下文

### 7. 路径穿越 → communitytools + strix + Claude-BugHunter
- communitytools `scenarios/path-traversal/`：编码/过滤绕过/目标文件清单/LFI→RCE/Jupyter 写文件
- strix `path_traversal_lfi_rfi.md`：「写文件≠可 HTTP 访问」内部 resolver 执行链
- Claude-BugHunter `hunt-lfi`：`php://filter` 链 → 无上传 RCE

### 8. 文件上传 → Agentic-Bug-Hunter + communitytools + AutoHunter(判定)
- Agentic-Bug-Hunter：10 技 bypass 表 + `multipart_mutator.py`（multipart 解析混淆工具）
- communitytools `scenarios/file-upload/`：NTFS junction、媒体 UNC 泄 NTLM、`.so` 模块阴影
- AutoHunter `prompts.py`：收洞三分法（txt 不够格/HTML-SVG 存 XSS/可执行=getshell）判定口径

### 9. SSTI → strix + pentest-agents + Argus(判定)
- strix `ssti.md`（19KB 类内最厚）：引擎指纹差分表 + 各引擎 RCE gadget + 沙箱逃逸 + Thymeleaf 假阳性辨析
- pentest-agents `ssti-hunter.md`：Jinja2 sandbox 黑名单测绘
- Argus：31337×31337 大数精确回显判定（防 7*7=49 巧合误报）

### 10. ELI → strix(SpEL 节) + Claude-BugHunter(hunt-springboot) + pentest-agents
- 各家均弱（最高 2 分）；strix SSTI 内 SpEL 专节 + Claude-BugHunter SpEL/Gateway 脚本 + pentest-agents ELI payload 表（rules/payloads.md）
- deepbounty 已有 `expression-engines.md`，吸收三方 SpEL/OGNL 案例即可，属补强而非换源

### 11. JWT → communitytools + pentest-agents + Agentic-Bug-Hunter
- communitytools `scenarios/jwt/`（13 个场景文件，最全）：none/alg 混淆/jku/kid/x5u/psychic-signatures/ECDSA nonce 复用/JWE 嵌套
- pentest-agents `hunt-oauth`（644 行）：CVE 案例 + 逐步狩猎法
- Agentic-Bug-Hunter `jwt_scanner.py`：离线锻造工具

### 12. 用户枚举 → communitytools + BountyGrimoire
- communitytools：存在性侧信道 oracle（错误校验顺序）+ 时序/锁定方法论
- BountyGrimoire `find-enumerable`：顺序 ID/Base64 GID/时序攻击
- AutoHunter 补充：「单独枚举通常不报」拒收口径（防浪费）

### 13. 越权 → AutoHunter + strix + communitytools
- AutoHunter `write_proof.py` + `prompts.py`：无害写证法（哨兵闭环/幂等回写/鉴权对照）——独家，直接移植
- strix `broken_function_level_authorization.md`：Actor×Action 矩阵 + 动词漂移/功能开关
- communitytools `scenarios/access-control/`：method/header/referer/多步/mass-assignment 路由

### 14. IDOR → pentest-agents + Argus(判定) + AutoHunter(取证)
- pentest-agents `hunt-idor`（791 行）：ID 操纵/方法变异/版本降级
- Argus：「无效 id 也 200 → 公开资源」基线（防公开资源误报）
- AutoHunter：看→改/删→量化规模升级链 + 无害证法
- Agentic-Bug-Hunter 补充：`h1_idor_scanner.py` 等专用脚本

### 15. 优惠/积分/抽奖 → communitytools + pentest-agents + VEGA
- communitytools：`coupon-stacking.md`/`gift-card-loop.md`/`price-manipulation.md`
- pentest-agents `hunt-business-logic`（906 行）：Coupon 堆叠/过期复用/竞态领取 + 美元量化纪律
- VEGA `vega-logic.md`：支付状态机（并发券/重复退款/价格篡改/状态回滚）

### 16. 竞态 → communitytools + Claude-BugHunter + strix
- communitytools `scenarios/race-conditions/`（12 场景）：PREDICT/PROBE/PROVE 方法论
- Claude-BugHunter `hunt-race-condition`：HTTP/2 单包攻击 + Turbo Intruder 脚本 + 双花判定（≥2 次 2xx）
- strix `race_conditions.md`：「串行拒绝、并发成功」Validation 标准

### 17. 重放 → communitytools + Claude-BugHunter + VEGA
- communitytools：订单确认/OTP/OAuth state/SAML 多通道重放场景
- Claude-BugHunter `hunt-session`：refresh-token 轮换 + 家族吊销（OAuth BCP）
- VEGA：登出后 Token/支付重放 curl 验证脚本

### 18. 验证码/短信绕过 → communitytools + VEGA + AutoHunter(判定)
- communitytools `CAPTCHA_BYPASS.md` + `scenarios/2fa/`（11 场景）：服务端校验失败优先序 + OTP 矩阵
- VEGA `vega-logic.md`：跨账号验证码/跳过步骤/短信限速（中国场景）
- AutoHunter：图形码回显忽略 vs 短信 OTP 回显可接管的三分法判定

### 19. 开放重定向 → BountyGrimoire + strix
- BountyGrimoire `find-callback`：双斜杠/Unicode 点/十进制 IP/OAuth redirect_uri
- strix `open_redirect.md`：userinfo/反斜杠/IDN/双重编码矩阵 + OAuth 劫持链

### 20. CORS → communitytools + Agentic-Bug-Hunter + Claude-BugHunter
- communitytools `cors-quickstart/cheat-sheet` + `scenarios/rest/cors-misconfiguration.md`
- Agentic-Bug-Hunter `cors_scanner.py`：ACAO/ACAC 分级严重度模型
- Claude-BugHunter `hunt-cors`：「仅凭证可读才 High」硬规则 + null-origin 分型

### 21. 敏感信息泄露 → VEGA + strix + pentest-agents
- VEGA `vega-leak.md`：中国场景密钥正则 + 误报过滤 + 严重性校准（独家本地化）
- strix `information_disclosure.md`：Triage Rubric（Critical→Informational）
- pentest-agents `hunt-info-disclosure`（866 行）+ `wordlists/secret-patterns.txt`
- AutoHunter 补充：EduSRC「死规矩四类 + 公开接口排除」

## WAF 绕过专项对比

| 来源 | 丰富度 | 核心资产 | 特色 |
|---|:-:|---|---|
| pentest-agents | 3 | `rules/waf-bypass-protocol.md` + `claude/agents/waf-profiler.md` | 7 级绕过阶梯（编码→标签→事件→无关键字 JS→解析差分→上下文逃逸→基础设施）；「禁止 3-5 次探针就放弃」纪律 |
| communitytools | 3 | `reconnaissance/reference/waf-edge-bypass.md` + `anti-bot-bypass.md` + 各类 waf-bypass scenario | 边缘/CDN 运维级绕过（直连 Origin 发现）+ 反 bot（JA3/指纹/cf_clearance）+ CAPTCHA 服务端绕过 |
| Agentic-Bug-Hunter | 3 | `commands/bypass-403.md` + `tools/waf_encoder.py` + `waf_response_analyzer.py` + `multipart_mutator.py` | 工具化最强：编码器/响应分析器/multipart 混淆器可直接跑；sqlmap tamper 族索引 |
| Claude-BugHunter | 3 | `security-arsenal/SKILL.md` + 各 hunt-* 绕过章节 | WAF 评估顺序（编码→解析歧义→协议层→厂商规则）方法论 + Always-Rejected 提交门 |
| strix | 2 | `vulnerabilities/semantic_confusion.md` | 「WAF 见 A、应用消费 transform(A)」差分心智模型 |
| AutoHunter | 2 | `tools/waf_advisor.py` | 按漏洞上下文排序的变形候选（轻量实用） |
| Argus | 2 | `tools/payload_mutator.py` | 编码族落地（URL 双编码/Unicode/注释/大小写） |
| VEGA | 2 | install.sh 种子 + `vega-exploit.md` | 战略型：「弃漏扫专攻逻辑」+ 移动端 API 切换 |
| pentest-ai-agents | 2 | `agents/web-hunter.md` | 工具 tamper 指导（sqlmap/Commix） |
| BountyGrimoire | 1 | 各 find-* 绕过节 | 应用层过滤绕过为主 |
| PentestGPT | 0 | — | 无 |

**WAF 学习结论**：以 pentest-agents 的 7 级阶梯为骨架，communitytools 补边缘/反 bot 维度，Agentic-Bug-Hunter 补工具化，Claude-BugHunter 补评估顺序方法论，strix 补差分心智——五家合并进 `references/waf-bypass.md`。

## 横向方法论吸收（不属单一漏洞类但高价值）

| 方法论 | 来源 | 文件 |
|---|---|---|
| counterevidence 三态闭环（confirmed/ruled_out/open_proof_gap） | strix | `skills/analysis/counterevidence.md` |
| 无害写证法（哨兵闭环/幂等回写） | AutoHunter | `app/agents/write_proof.py` |
| 误报治理判定（SSTI 大数回显/IDOR 无效基线/XSS 转义排除） | Argus | `agents/lats/actions.py` |
| 指纹→scenario 路由契约 | communitytools | `skills/injection/reference/INDEX.md` |
| 7 问门 triage | Agentic-Bug-Hunter | `skills/triage-validation/SKILL.md`（deepbounty 已吸收） |
| 业务=状态机建模 | VEGA | `agents/vega-logic.md` |
| 严重度诚实校准 | strix | `skills/analysis/severity_calibration.md` |
| 「什么算洞」EduSRC 口径 | AutoHunter | `app/agents/prompts.py` |
