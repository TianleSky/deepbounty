# SSTI 增量手册（DeepBounty 吸收版）

> 基线：Claude-BugHunter `hunt-ssti/SKILL.md`。检查点映射：SSTI001 运算回显 / SSTI002 引擎指纹 / SSTI003 沙箱逃逸读文件 / SSTI004 RCE。

## 最优来源

- strix `strix/skills/vulnerabilities/ssti.md`（19KB 类内最厚：引擎指纹差分表 + 各引擎 gadget + 假阳性辨析）
- pentest-agents `rules/payloads.md` SSTI 节 + `ssti-hunter.md`（Jinja2 黑名单测绘）
- Argus `agents/lats/actions.py`（**大数精确回显判定**，防误报）
- communitytools `scenarios/ssti/double-render-quote-free-bypass.md`（双渲染+无引号绕过）

## 增量 1：大数精确回显判定（Argus，防 7×7=49 巧合）

探测运算一律用大数：`{{31337*31337}}` = 982081669——页面天然出现该数的概率≈0；
`7*7=49` 可能撞页面既有数字造成假阳性。判定要求**精确字符串匹配**运算结果。

## 增量 2：引擎指纹差分表（strix）

| payload | Jinja2 | Twig | Freemarker | Velocity | Thymeleaf | Smarty |
|---|---|---|---|---|---|---|
| `{{7*7}}` | 49 | 49 | 不解析 | 不解析 | 不解析 | 不解析 |
| `${7*7}` | 不解析 | 不解析 | 49 | 49 | 49* | 不解析 |
| `{{7*'7'}}` | 7777777 | 49 | 报错 | 不解析 | — | 报错 |
| `#{7*7}` | 不解析 | 不解析 | 49 | 不解析 | 49 | 不解析 |
| `*{7*7}` | — | — | — | — | 49（Thymeleaf 特有） | — |

*Thymeleaf 的 `${}` 是变量表达式非运算，需 `#{...}` 或 `*{...}` 上下文——strix 有假阳性专节辨析。

## 增量 3：双渲染+无引号绕过（communitytools 独家场景）

`render_template_string(stored_value)` 二次渲染 + 黑名单 `__`/`file`/`write` + autoescape 转义引号时：
- 构造 `__`：`(config|list)[5][6]` 取字符拼接
- 构造标识符字符串：`dict(name=1)|first` 无引号产出字符串
- 命令经 hex 放 `?c=` query 参数侧信道传入

## 增量 4：Jinja2 沙箱黑名单测绘（pentest-agents）

先探测哪些关键字被拦（`config`/`__class__`/`request`/`lipsum`/`cycler`），再选 gadget 链；
被拦时走 `|attr()` 拼接、`request.args` 传键名、十六进制/八进制字符串解码。

## 判定纪律

- SSTI001（运算回显）→ SSTI002（指纹）→ SSTI003（读文件）→ SSTI004（RCE）逐级升级，
  每级都要独立证据；只到 001 的条目标注「模板解析确认、利用面待测绘」
