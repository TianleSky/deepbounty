# 表达式 / 模板引擎指纹与发现（非穷尽）

供 SSTI / 表达式注入测试要点引用。本表只收录**公开资料中的检测与引擎识别**（算术求值、定界符、报错类名），**不是**利用手册。

**判定门槛**：参数被服务端当作表达式/模板求值（如 `7*7`→`49`，或报错类名点名引擎）即可记 `found`。不要求、也不应把「弹出计算器 / 执行系统命令」当作成立条件。

**本清单不是闭集。** 引擎可配置自定义定界符；同一 `${}` 可被多种 Java 解释器吃掉。识别失败时按下文「未知引擎发现」继续，不得因不在表中就判 `tested_not_found`。

公开依据：
- PortSwigger Research / Web Security Academy：SSTI 明文上下文用数学表达式探测；`{{7*'7'}}` 在 Twig 得 `49`、Jinja2 得 `7777777`；无效语法的报错常自报引擎名。
- OWASP *Expression Language Injection*、CWE-917：用户输入进入 Java EL 解释器；JSP/JSF Unified EL、Spring SpEL 等。
- Tenable 等公开归类：JSP EL、OGNL（Struts/WebWork）、MVEL、SpEL 同属表达式注入族。

---

## 一、先分族：模板引擎 vs 表达式语言

| 族 | 典型场景 | 矩阵 `vuln_type` | 要点前缀 |
| --- | --- | --- | --- |
| 服务端模板注入 | 用户输入被拼进模板再渲染（邮件模板、预览、主题、CMS） | SSTI 模板注入 | SSTI |
| Java 表达式注入 | 用户输入被交给 EL/OGNL/SpEL/MVEL/JEXL 求值（标签、规则引擎、Struts、Spring） | 表达式注入 | ELI |

`${7*7}`→`49` 时**两族都可能**，必须继续用下表分叉，禁止只测一种定界符就停。

---

## 二、已知定界符族（检测探针，命中看是否算出 49 或引擎报错）

同一探针可能命中多种引擎，**单次 49 不能定种**。

| 探针（把 `7*7` 换成非常见常数以免和页面原有数字撞车，如 `41*43`→`1763`） | 公开资料中常见引擎族 |
| --- | --- |
| `{{7*7}}` | Jinja2、Twig、Nunjucks、Pebble、部分 Tornado |
| `${7*7}` | FreeMarker、Thymeleaf/`th:text`、Java Unified EL、SpEL、部分 Velocity/Mako |
| `#{7*7}` | JSF/Unified EL 延迟求值、部分 SpEL、FreeMarker legacy、Ruby `#{}`、Pug |
| `%{7*7}` | OGNL（Struts2 等） |
| `*{7*7}` / `@{7*7}` | Thymeleaf 选择/链接表达式 |
| `[[${7*7}]]` 或 `[(${7*7})]` | Thymeleaf **内联**（普通 `${}` 在文本区可能不求值） |
| `<%= 7*7 %>` | ERB、EJS、JSP scriptlet 表达式 |
| `@(7*7)` | ASP.NET Razor |
| `{7*7}` / `[[7*7]]` | Smarty（默认定界或改过的定界） |
| `#set($x=7*7)$x` | Apache Velocity（常**不能**靠裸 `${7*7}` 做乘法） |
| `<#assign x=7*7>${x}` | FreeMarker 指令体（与 `${}` 插值互补） |

**混淆探针（PortSwigger 决策树常用）**：`{{7*'7'}}` → Jinja2 字符串重复得 `7777777`；Twig 数值强制得 `49`。

**多引擎 polyglot（触发解析错误、堆栈常带类名）**：PortSwigger 系公开写法 `${{<%[%'"}}%\`

---

## 三、Java 侧再分种（算术之后，用**无命令执行**的差异）

| 引擎 | 常见框架痕迹 | 相对稳妥的识别 | 报错类名线索（堆栈/响应体） |
| --- | --- | --- | --- |
| Unified EL | JSP/JSF、`.jsp`/`.xhtml`、`JSESSIONID` | `${}` 与 `#{}` 均可；`T(...)` **不是** EL 语法 | `javax.el.` / `jakarta.el.ELException` |
| SpEL | Spring、Thymeleaf、`spring:eval` | 独有类型运算符：`T(java.lang.Math).abs(-7)`→`7` | `org.springframework.expression` / `SpelEvaluationException` |
| OGNL | Struts2 `.action`、Confluence 历史面、WebWork | `%{7*7}`；`${}` 在部分版本也会进 OGNL | `ognl.OgnlException` |
| MVEL | 规则引擎、部分 Seam/老 JBoss | 整段参数当脚本（无定界也求值）或 `@{}`；以类名为准 | `org.mvel2.` |
| JEXL | Apache Commons 规则/报表 | 类名为准，定界常像 `${}` | `org.apache.commons.jexl` |
| FreeMarker | `.ftl`、Java CMS/邮件 | `${7*7}`→49；`${7*'7'}` 常不按 Jinja 方式求值 | `freemarker.core.ParseException` |
| Velocity | `.vm` | 优先 `#set` 探针 | `org.apache.velocity.exception` |
| Thymeleaf | Spring Boot 默认视图 | 文本节点试 `[[${7*7}]]`；属性里还有 `th:*` | 堆栈含 `thymeleaf` / 内嵌 SpEL 异常 |
| Pebble | Java `{{ }}` | `{{7*7}}`→49，但不是 Jinja（无 Python 串乘） | `pebble.error` / `mitchellbosecke` |

框架线索只作**先验**（Cookie、URL 后缀、HTML 注释里的模板路径），最终以探针求值或报错类名为准。

---

## 四、未知引擎发现（强制能力，表外也要测）

出现任一信号即进入本流程，**禁止**「表里没有这个引擎 → 不测」：

1. **收证据**：5xx 响应体、`Exception`/`Caused by` 全类名、模板文件后缀（`.ftl` `.vm` `.pebble` `.mustache` `.liquid` `.hbs`）、HTML 注释中的引擎 banner。
2. **用类名反查**：把从未见过的 `com.xxx.template` / `org.xxx.el` 当新引擎名，记入矩阵 `notes`，再按其文档补一条算术探针（定界符从报错的 “unexpected `{{`” 里抄）。
3. **扫定界符族，不扫利用链**：除上表外继续试页面/JS 里出现过的配对符号（如 `[% %]`、`{* *}`、`{{= }}`、双花括号变体）。任意一对让算术生效，即新引擎/自定义定界，记 `found` 并写清「未知引擎 + 所用定界 + 求值结果」。
4. **盲/无回显**：对比基线时延；若引擎支持副作用，只用**无害时延**（模板侧 sleep/等待类函数，且目标允许）或带外 DNS，不把弹计算器当门槛。
5. **过滤后换皮**：定界符被剥/拦时试 URL 编码、大小写、插空格（`${ 7*7 }`）、拆分（`{{` 与 `}}` 分参数）、HTML 实体；仍求值则 `found`，拦死但有解析报错则 `filtered`。
6. **双族交叉**：Java 站即使先命中 FreeMarker，仍要抽测 `%{}`、`T(java.lang.Math)`、`[[${}]]`，避免漏掉同进程里的 OGNL/SpEL。

---

## 五、适用线索（何时必须测，而不是只看参数名叫 template）

- 参数进入预览、邮件正文、短信模板、代码生成、报表、规则条件、排序公式、动态视图名。
- 反射型 XSS 已成立但输入像模板定界符（PortSwigger：明文模板上下文常被误判成 XSS）。
- 响应或报错出现 `template`/`freemarker`/`velocity`/`ognl`/`spel`/`thymeleaf`/`jinja`。
- JSON/XML 字段把用户字符串原样套进服务端表达式（规则引擎、工作流）。
