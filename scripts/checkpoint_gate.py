# -*- coding: utf-8 -*-
"""DeepBounty 检查点门禁（checkpoint gate）：

1. **双向自校验**：common.py 的 VULN_CHECKPOINTS（机读集）与 references/checkpoints.md
   （人读文档）必须严格一致——修 tyang-skill2 "SQL004 在 md 有但机读集没有，答了反被判越界"。
   从 checkpoints.md 解析全部编号（正则会表 `SQL001` 等），与 VULN_CHECKPOINTS 双向 diff。
2. **全覆盖校验**：所有矩阵条目（有要点类型且 status∈{tested_not_found,doubtful,filtered}）
   的 checkpoint_response 必须覆盖该类型编号集全集（与 check_vuln_mining 同源，此处独立可跑）。

用法：
    python checkpoint_gate.py --project <id> [--data-root pentest-data]
"""

import argparse
import glob
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c

CHECKPOINTS_MD = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "..", "references", "checkpoints.md")


def parse_md_checkpoints(md_path):
    """从 checkpoints.md 解析 前缀→编号集（匹配表格中的编号列与正文编号）。"""
    found = {}
    if not os.path.exists(md_path):
        return found
    with open(md_path, "r", encoding="utf-8") as f:
        text = f.read()
    for m in re.finditer(r"\b([A-Z]{2,6})(\d{3})\b", text):
        prefix, num = m.group(1), m.group(2)
        found.setdefault(prefix, set()).add("%s%s" % (prefix, num))
    return found


def self_check(errors):
    """common.py ↔ checkpoints.md 双向一致性。"""
    md = parse_md_checkpoints(CHECKPOINTS_MD)
    md_flat = {k: v for k, v in md.items() if k in c.VULN_CHECKPOINTS or k in
               {"SQL", "XSS", "CMDI", "SSRF", "PATH", "UPLOAD", "SSTI", "ELI", "XXE",
                "NOSQLI", "JWT", "ENUM", "AUTHZ", "PRIZE", "RACE", "REPLAY", "SMS"}}
    for prefix, ids in c.VULN_CHECKPOINTS.items():
        md_ids = md_flat.get(prefix, set())
        missing_in_md = ids - md_ids
        if missing_in_md:
            errors.append("[自校验] 机读集 %s 有编号 %s 但 checkpoints.md 未定义——两处必须同步"
                          % (prefix, "/".join(sorted(missing_in_md))))
    for prefix, md_ids in md_flat.items():
        if prefix not in c.VULN_CHECKPOINTS:
            errors.append("[自校验] checkpoints.md 定义了 %s 编号但 common.py VULN_CHECKPOINTS 无此前缀"
                          % prefix)
            continue
        missing_in_code = md_ids - c.VULN_CHECKPOINTS[prefix]
        if missing_in_code:
            errors.append("[自校验] checkpoints.md 有编号 %s 但机读集 %s 未收录——"
                          "子代理答了会被判 KEY 越界（SQL004 事故），必须同步"
                          % ("/".join(sorted(missing_in_code)), prefix))


def coverage_check(paths, errors):
    """全部矩阵的 checkpoint_response 全覆盖校验。"""
    for fp in sorted(glob.glob(os.path.join(paths["vuln_matrix_dir"], "*.json"))):
        uid = os.path.splitext(os.path.basename(fp))[0]
        matrix = c.load_json(fp, default={}) or {}
        entries = []
        for pname, ents in (matrix.get("params") or {}).items():
            for e in ents or []:
                entries.append((pname, e))
        for e in matrix.get("_url_level", []) or []:
            entries.append(("_url_level", e))
        for pname, e in entries:
            if not isinstance(e, dict):
                continue
            st = e.get("status")
            vt = e.get("vuln_type", "")
            ck_ids = c.checkpoint_ids_for(vt)
            if not ck_ids or st not in c.FILTER_PROBE_REQUIRED_STATUS:
                continue
            cr = e.get("checkpoint_response")
            if not isinstance(cr, dict):
                errors.append("[要点] %s %s 漏洞[%s] 缺 checkpoint_response" % (uid, pname, vt))
                continue
            missing = sorted(ck_ids - set(cr.keys()))
            if missing:
                errors.append("[要点] %s %s 漏洞[%s] checkpoint_response 缺 %s（须全覆盖）"
                              % (uid, pname, vt, "/".join(missing)))


def main():
    p = argparse.ArgumentParser(description="DeepBounty 检查点门禁（自校验+全覆盖）")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    args = p.parse_args()
    paths = c.project_paths(args.data_root, args.project)
    errors = []
    self_check(errors)
    coverage_check(paths, errors)
    if errors:
        print("【检查点门禁硬错误（%d）】" % len(errors))
        for e in errors:
            print("  - " + e)
    else:
        print("【检查点门禁通过】机读集与 checkpoints.md 一致；全部要点应答全覆盖。")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
