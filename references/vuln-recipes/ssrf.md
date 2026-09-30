# SSRF 增量手册（DeepBounty 吸收版）

> 基线：Claude-BugHunter `hunt-ssrf/SKILL.md`（黑名单绕过族已全）。检查点映射：SSRF001 OOB 回连 / SSRF002 内网可达差异 / SSRF003 云元数据 / SSRF004 协议走私。

## 最优来源

- Agentic-Bug-Hunter `skills/web2-vuln-classes/SKILL.md` §SSRF（11 种 IP bypass + triage 硬规则）
- communitytools `skills/injection/reference/scenarios/ssrf/`（稀缺边角场景）
- BountyGrimoire `.claude/skills/find-ssrf`（参数优先级清单）
- VEGA `agents/vega-exploit.md` PoC 模板 D（中国 SRC 风格 DNSLOG 举证）

## 增量 1：triage 硬规则（Agentic-Bug-Hunter，防浪费）

- **仅 DNS 回调 ≠ 可提交**：DNS 出网但 HTTP 不出网（常见 egress 只放行 53）时，必须补 HTTP 回连或内网差异，否则只能 open
- 云元数据 `169.254.169.254` 拿到 IAM 临时凭证才算 SSRF003 通过；只返回 404/超时不算
- 重定向链绕过：目标校验 URL 但不校验 302 跳转目标 → 自建跳转服务（或 `http://httpbin.org/redirect-to?url=` 类公开跳转）

## 增量 2：参数优先级清单（BountyGrimoire .claude/skills/find-ssrf）

按命中率排序测：`url`/`uri`/`link`/`src`/`source`/`target`/`dest`/`destination`/`redirect`/`fetch`/
`load`/`proxy`/`callback`/`webhook`/`feed`/`host`/`site`/`path`/`image`/`avatar`/`pdf`/`import`/`export`。
文件上传处的「从 URL 导入」、PDF 生成器、头像抓取、webhook 配置是四大高发功能点。

## 增量 3：稀缺边角场景（communitytools）

- **header-name 走私打 Redis**：SSRF 可控部分 header 名时，CRLF 注入 gopher 等价物
- **UTF-8 二进制丢失**：某些栈 fetch 后强制转 UTF-8 破坏二进制响应——图片/PDF 类内网服务探测会误判为不可达，改用响应长度/状态码差异而非内容
- **DNS rebinding 双 A 记录**：自建域名 TTL=0 双 A（公网+内网），绕过「解析时校验、请求时重解析」的 TOCTOU

## 增量 4：VEGA 举证模板（中国 SRC 口径）

DNSLOG 举证四件套：① 请求包（含目标参数）② DNSLOG 平台命中截图（含子域时间戳）
③ 唯一子域命名 `<urlid>-<rand>.dnslog.cn` ④ 复现 curl。与 deepbounty evidence-standard 的 OOB 证据格式兼容，直接复用命名规范。
