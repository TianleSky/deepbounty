# 路径穿越增量手册（DeepBounty 吸收版）

> 基线：Claude-BugHunter `hunt-lfi/SKILL.md`。检查点映射：PATH001 穿越读取 / PATH002 编码绕过 / PATH003 协议包装器利用。

## 最优来源

- communitytools `skills/injection/reference/scenarios/path-traversal/`（编码/过滤绕过/目标清单/LFI→RCE）
- strix `strix/skills/vulnerabilities/path_traversal_lfi_rfi.md`（内部 resolver 执行链）
- Agentic-Bug-Hunter §LFI（LFI→RCE 升级路径）

## 增量 1：目标文件清单分级（communitytools）

按证明力排序（取证时从无害到敏感）：
1. 存在性证明：`/etc/hostname`、`/windows/win.ini`、`/etc/issue`
2. 指纹信息：`/etc/os-release`、`/proc/version`、应用配置文件名
3. 利用价值：应用配置（数据库串——只截取证明行并打码）、日志（log poisoning 前置）、SSH 私钥（**只证明可读，不取全文**）

## 增量 2：「写文件 ≠ 可 HTTP 访问」执行链（strix 独家）

拿到任意文件写后不要直接报 RCE——确认：
- 写入路径是否在 webroot / 是否有执行权限的解析器（php/jsp/aspx）
- 不在 webroot 时的替代链：写 cron / 写 authorized_keys / 写配置（如 Jupyter `jupyter_notebook_config.py`）/
  覆盖模板文件（SSTI 化）/ 覆盖 `.so` 模块（社区 NTFS junction 思路的 Linux 版）
- 内部 resolver 场景：文件被应用自身（非 HTTP）读取解析时，按「配置注入」而非「文件读」建模

## 增量 3：编码绕过族补全（communitytools）

- 双重 URL 编码：`..%252f`
- Unicode/UTF-8 超长编码：`..%c0%af`（`/` 的 2 字节超编）、`..%e0%80%af`（3 字节）
- 绝对路径替换：过滤 `../` 时直接打 `/etc/passwd` 或 `C:\windows\win.ini`（很多过滤只看相对序列）
- 截断：PHP <5.3 `..../etc/passwd%00`；Java 栈 `..;/`（Tomcat 分号语义）

## 判定纪律

- PATH001 通过标准：同一参数 `../../../../etc/hostname` 读成功 + `../nonexistent_<rand>` 返回不同（排除默认兜底页）
- 与 XXE 互斥（Argus 判定逻辑）：Content-Type 为 XML 且实体可用时优先 XXE 通道，不重复记 PATH
