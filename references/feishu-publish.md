# 把已通过审核的漏洞报告发布到飞书

不参与挖掘，不改 `review_status`，不进入 `check_mining.py` / `evidence_gate.py`。失败只打印，复盘照常进行。

登录用户身份用 `lark-cli --as user`。表已建好，不要另建。

- 表格：https://lcncmz00uxyz.feishu.cn/base/XxNlbBsMIaZpjusPAAzcCWRJnqg
- `base_token`：`XxNlbBsMIaZpjusPAAzcCWRJnqg`
- `table_id`：`tblZKX72Tt3vQsZZ`（表名：漏洞）
- 新增列：**飞书文档**（文本，`style.type=url`）。列已存在则不重复建。其它技能不写这一列也可以。

## 何时跑

DeepBounty 收到尾时由主代理自己执行，不要让用户手动跑。时机是 P4 出口门禁核对之后。发布技能的最终报告，满足下面任一条件且报告文件存在：

- `review_status=approved`
- `review_status=pending_review`，且 `validation/<vuln_id>/verdict.json` 里 `verdict` 为 `confirmed`（盲验证已通过，清单还没改成 approved 也算最终报告）

`rejected` 不发布。还在写、没有确认结论的 `pending_review` 不发布。没有可发布条目就跳过。

```powershell
python .claude\skills\deepbounty\scripts\publish_feishu.py --project <id>
python .claude\skills\deepbounty\scripts\publish_feishu.py --project <id> --vuln-id VULN-VD-URL00010-0001
```

## 幂等

- 报告上已有 `feishu_doc_url`：不再调用 `docs +create`。
- 表格按 `VULN-VD号` 搜索。已有行只更新「飞书文档」；没有行才按现有列整行新建（标题、漏洞类型、危害等级、项目、接口、业务危害、VULN-VD号、报告路径、状态、发现时间，外加飞书文档）。
- 成功后把 `feishu_doc_url`、`feishu_record_id`、`feishu_published_at` 写回该报告对象。这三个字段缺省不影响审核。

## 截图

原始 `reports/*.md` 不改。脚本在 `pentest-data/{id}/tmp/feishu/{vuln_id}/` 做副本：能相对报告文件找到的本地图，以及正文里的 Base64 图片，复制成 `![说明](@./assets/文件名)` 再交给 `docs +create`。`http` / `https` 链接保持原样。代码块里的图片语法不处理。找不到的本地路径改成「图片未找到」文字，不把绝对路径直接传给 CLI。

未登录时先看 `lark-cli auth status --json --verify`，不要手写假链接。
