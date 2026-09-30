# 文件上传增量手册（DeepBounty 吸收版）

> 基线：Claude-BugHunter `hunt-file-upload/SKILL.md`。检查点映射：UPLOAD001 危险类型上传成功 / UPLOAD002 上传后可访问执行。

## 最优来源

- Agentic-Bug-Hunter §上传（10 技 bypass 表 + `bughunter/tools/multipart_mutator.py` 可执行工具）
- communitytools `scenarios/file-upload/`（NTFS junction / 媒体 UNC 泄 NTLM / `.so` 模块阴影）
- AutoHunter `app/agents/prompts.py`（**收洞三分法判定口径**，防误报）

## 增量 1：multipart 解析混淆（Agentic-Bug-Hunter 工具化）

`multipart_mutator.py` 生成畸形 multipart：
- filename 参数重复（第一个合法第二个恶意，解析器取其一）
- Content-Type 头重复/大小写混淆/参数内嵌引号
- boundary 前缀/后缀变异（`--xx` vs `----xx`）、LF-only 换行
- filename 编码：`filename*=UTF-8''shell.php`（RFC 5987）绕黑名单

## 增量 2：高阶落地场景（communitytools）

- **NTFS junction/ADS**：Windows 目标 `shell.php:.jpg`、目录穿越文件名 `../../wwwroot/x.aspx`
- **媒体文件 UNC**：Office/图片处理库解析远程模板 → 泄 NTLM hash（Responder 收）
- **`.so`/模块阴影**：上传同名共享库到 LD_LIBRARY_PATH 优先路径
- **压缩包炸弹/zip slip**：解压场景 `../../` 条目

## 增量 3：收洞三分法（AutoHunter 判定口径，直接移植）

| 上传结果 | 判定 | 处置 |
|---|---|---|
| 只能传 txt/图片且不可解析 | 不够格 | 不报，转其他参数 |
| HTML/SVG 可访问 | 存储型 XSS 级 | 按 XSS 举证（XSS002 标准） |
| 可执行脚本（php/jsp/aspx）+ 可访问 | getshell | UPLOAD001+002 全过，L3 高危 |

## 判定纪律（对齐 evidence-standard）

- UPLOAD002 必须给出**上传后 URL 的访问响应**（200 + 执行结果 marker），只有上传响应 200 不算
- 执行证明用无害 marker：`phpinfo()` 截图打码服务器路径、`echo '<rand>'`、数学运算回显
- 禁止上传真实 webshell 留后门——验证完立即调用删除接口或联系哨兵文件自清理
