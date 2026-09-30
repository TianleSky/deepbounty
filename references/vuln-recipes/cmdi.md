# 命令注入增量手册（DeepBounty 吸收版）

> 基线：Claude-BugHunter `hunt-rce/SKILL.md`。检查点映射：CMDI001 时间延迟 / CMDI002 OOB 回连 / CMDI003 回显差异。

## 最优来源

- strix `strix/skills/vulnerabilities/argument_injection.md`（**独家**：无 shell 参数注入全模型）
- strix `rce.md` + pentest-agents `skills/hunt-rce/SKILL.md`（925 行：无空格绕过/CVE 链）

## 增量 1：参数注入四原语（strix argument_injection，独家硬核）

攻击面不止 shell 元字符——数据到达可信 CLI 的 argv 即可控：

1. **选项/子命令注入**：值落在操作数位置但以 `-`/`--` 开头 → 被解析为选项。
   盘点高危选项类：output/upload/extraction/log/plugin/template/config 路径、
   URL scheme/proxy/cert/credential、hook/helper/filter/interpreter、子命令（import/export/restore/diagnostic）。
   检查 `--` end-of-options 是否存在且位置正确（子命令后可能切第二个解析器）。
2. **参数边界突破**：需要「重解析」组件——shell 拼接、Windows 引号不匹配、换行/NUL 敏感启动器、
   数组 join 后又 split 的 wrapper、CGI 映射。区分 `["tool","user --flag"]`（一个元素，execve 不拆）
   vs `["tool","user","--flag"]`（真注入）。日志把数组渲染成字符串会**假阳性**，要看子进程真实 argv。
3. **响应/配置/认证文件**：`@response-file`（编译器/JVM 工具）、`--config`/credential 文件、
   换行分隔 kv 文件——控制字符造新指令。正确 shell 引号**保护不了**之后被另一语法 tokenize 的文件。
4. **Windows Unicode→ANSI Best-Fit**：窄字符 API（`GetCommandLineA`/窄 `main`）把 Unicode 映射进 ANSI
   代码页，软连字符→`-`、全角斜杠→`/`、兼容引号→`"`。校验在宽字符侧、消费在窄字符侧即绕过。

## 增量 2：无空格/无字母绕过（pentest-agents hunt-rce）

- 无空格：`$IFS$9`、`{cat,/etc/passwd}`、`<` 重定向、tab（`%09`）
- 无字母数字：`${PATH:0:1}` 切片取字符构造命令（bash）
- 通配符执行：`/???/??t /???/??ss??` → `/bin/cat /etc/passwd`

## 判定纪律（strix Validation 移植）

- 展示**最终 argv 或二级解析器输入**，不只是应用日志行
- 候选 payload 与「同字节保持字面操作数」的对照组配对
- 区分四个不同原语等级：选项控制 / 额外参数控制 / 任意指令控制 / 命令执行——报告里写清拿到哪一级
- 黑盒时：普通操作数 vs 选项前缀变体 vs 分隔符变体 vs 控制字符变体 vs 平台 Unicode 变体，五组对照
