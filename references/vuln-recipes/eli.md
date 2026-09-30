# ELI 表达式注入增量手册（DeepBounty 吸收版）

> 基线：Claude-BugHunter `hunt-springboot/SKILL.md`（SpEL 节）+ deepbounty 自有 `expression-engines.md`。
> 检查点映射：ELI001 表达式求值回显 / ELI002 引擎指纹 / ELI003 沙箱逃逸 / ELI004 RCE。
> 各家公开仓库此类均弱（最高 2 分），本手册为三方增量合订，属补强而非换源。

## 最优来源

- strix `ssti.md` 内 SpEL 专节（Spring 上下文）
- Claude-BugHunter `hunt-springboot/SKILL.md`（SpEL/Gateway 脚本注入）
- pentest-agents `rules/payloads.md` ELI 节（OGNL/MVEL/SpEL 速查）

## 增量 1：引擎探测速查（pentest-agents + strix 合订）

| 引擎 | 探测 payload | 指纹特征 |
|---|---|---|
| SpEL | `#{31337*31337}`、`T(java.lang.Math).random()` | Spring 栈、报错含 `SpelEvaluationException` |
| OGNL | `%{31337*31337}`、`(31337*31337)` | Struts2/Confluence，报错含 `ognl.` |
| MVEL | `@{31337*31337}` | Drools/Mule 上下文 |
| JEXL | `${31337*31337}`（与 EL 区分看报错） | `JexlException` |
| Unified EL | `${31337*31337}` | JSP/JSF，报错含 `ELException` |
| Thymeleaf 预处理 | `__${31337*31337}__::x` | 双下划线预处理语法 |

## 增量 2：Spring 特化入口（Claude-BugHunter hunt-springboot）

- Spring Cloud Gateway `AddResponseHeader` 等 filter 的 SpEL 求值
- `@Value`/`@PreAuthorize` 注解参数流经用户输入的路径
- Spring Data REST 查询参数、Actuator `env`/`jolokia` 暴露面（先测暴露再谈注入）

## 增量 3：OGNL 沙箱逃逸要点

- Struts2 系：`_memberAccess` 静态方法访问开关 → `#runtime.exec()`
- Confluence 系：`\u0027` 编码绕过引号过滤、`@java.lang.Runtime@getRuntime()` 静态调用
- 黑名单绕过：反射 `getClass().forName()` 拼接、字符串分段 `concat`

## 判定纪律

- ELI001 用大数运算（同 SSTI 的 31337×31337 纪律）
- 与 SSTI 的边界：模板引擎语法（`{{}}`）归 SSTI；Spring/Struts 上下文表达式（`#{}`/`%{}`）归 ELI；
  不确定时按报错堆栈定类，矩阵 vuln_type 以报错证据为准
