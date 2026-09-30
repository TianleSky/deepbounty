# XSS 增量手册（DeepBounty 吸收版）

> 基线：Claude-BugHunter `hunt-xss/SKILL.md` + `hunt-dom/SKILL.md`。检查点映射：XSS001 无害 marker 回显上下文 / XSS002 执行证明（alert/控制台/OOB）。

## 最优来源

- pentest-agents `skills/hunt-xss/SKILL.md`（789 行：CVE 元分析 + 判定树 + 检测旋转阶梯）
- communitytools `skills/client-side/reference/scenarios/`（11 个影响链场景）
- Claude-BugHunter hunt-xss（CSP/Angular CSTI 硬变体，基线已强）

## 增量 1：现代前端 XSS 判定树（pentest-agents）

- **mXSS**：innerHTML 二次解析变异——`<svg><style><img src=x onerror=...>` 类 payload 在序列化/重解析后变异执行；DOMPurify 旧版本绕过按 CVE 年份索引（先指纹 DOMPurify 版本再选 CVE payload）
- **postMessage**：先枚举 `window.addEventListener('message')` 监听器，检查 origin 校验缺失/正则绕过（`evil.com` 后缀、子域）；sink 为 innerHTML/eval 才升级
- **检测旋转阶梯**：payload 被拦时按「标签旋转→事件旋转→编码旋转→上下文逃逸」顺序换，不要同族重试（与 waf-bypass.md 阶梯一致）

## 增量 2：影响链场景库（communitytools，回答"有 XSS 然后呢"）

cookie 窃取只是起点；11 个升级场景包括：会话劫持→钓鱼覆盖层→键盘记录→内网端口扫描→
CSRF token 窃取后自动提交→存储型蠕虫传播。提交报告时按目标业务选最高影响链写危害，
不要只写「可弹窗」。

## 增量 3：误报排除（Argus 判定逻辑）

- 反射内容经 HTML 实体转义（`&lt;`）→ 不算，除非找到编码绕过
- 反射在 JS 字符串内但引号被转义 → 试 `\` 逃逸（`\"` → `\\"` 失效时）
- CSP `default-src 'self'` 且无 unsafe-inline → 标注「利用受限」，降 severity 不删条目

## 盲 XSS 纪律（基线已有，强化）

盲 XSS（后台/客服面板）一律走 OOB（deepbounty `oob_client.py` 起 interactsh，
payload 用 `<script src=https://OOB/x>`），命中即 XSS002 通过；无 OOB 命中只能 open。
