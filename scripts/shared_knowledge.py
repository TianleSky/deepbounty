# -*- coding: utf-8 -*-
"""DeepBounty 项目级共享情报库（shared knowledge，借 Argus shared_knowledge）。

所有 miner/bypass 子代理实时共享：WAF 指纹、拦截规则、**已验证有效的绕过手法**、
有效 payload、端点信号。某分支突破后同法自动广播——其他子代理遇到相同指纹直接复用，
不再重复交学费（修 tyang-skill2 各子代理信息孤岛、同一 WAF 反复硬撞）。

数据文件：shared-knowledge.json
用法：
    python shared_knowledge.py --project <id> show
    python shared_knowledge.py --project <id> add-waf --host api.x.com --fingerprint "403+Server: cloudflare" --note "..."
    python shared_knowledge.py --project <id> add-bypass --host api.x.com --guard "空格过滤" --technique "/**/替代" --evidence "URL00012 id 参数布尔盲注成功"
    python shared_knowledge.py --project <id> add-payload --vuln-type SQL注入 --payload "'||(SELECT...)" --context "数字型无引号" --success
    python shared_knowledge.py --project <id> query --host api.x.com [--guard "空格"]
    python shared_knowledge.py --project <id> export-global          # 项目结束沉淀到全局记忆
    python shared_knowledge.py --project <id> import-global          # 开挖前记忆预热
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c


def load(paths):
    return c.load_json(paths["shared_knowledge"], default={
        "_note": "项目级共享情报（所有子代理实时读写；突破手法即广播）",
        "waf": [], "bypasses": [], "payloads": [], "signals": [],
        "created": c.now_iso(),
    })


def save(paths, doc):
    doc["updated"] = c.now_iso()
    c.atomic_write_json(paths["shared_knowledge"], doc)


def cmd_show(paths):
    doc = load(paths)
    print("[WAF 指纹] %d 条" % len(doc.get("waf", [])))
    for w in doc.get("waf", []):
        print("  - %s | %s | %s" % (w.get("host"), w.get("fingerprint"), w.get("note", "")))
    print("[有效绕过] %d 条" % len(doc.get("bypasses", [])))
    for b in doc.get("bypasses", []):
        print("  - host=%s guard=%s → %s（证据:%s）"
              % (b.get("host") or "全局", b.get("guard"), b.get("technique"), b.get("evidence", "")[:60]))
    print("[有效 payload] %d 条" % len(doc.get("payloads", [])))
    for p in doc.get("payloads", []):
        mark = "OK" if p.get("success") else "NG"
        print("  - [%s][%s] %s | %s" % (mark, p.get("vuln_type"), p.get("payload", "")[:60], p.get("context", "")[:40]))


def cmd_add_waf(paths, args):
    doc = load(paths)
    for w in doc.get("waf", []):
        if w.get("host") == args.host and w.get("fingerprint") == args.fingerprint:
            print("[已存在] 该 WAF 指纹已登记")
            return
    doc.setdefault("waf", []).append({
        "host": args.host, "fingerprint": args.fingerprint,
        "note": args.note or "", "seen_at": c.now_iso(),
    })
    save(paths, doc)
    print("[WAF] 已登记：%s | %s" % (args.host, args.fingerprint))


def cmd_add_bypass(paths, args):
    doc = load(paths)
    entry = {
        "host": args.host or "", "guard": args.guard, "technique": args.technique,
        "evidence": args.evidence or "", "added_by": args.by or "", "at": c.now_iso(),
    }
    doc.setdefault("bypasses", []).append(entry)
    save(paths, doc)
    print("[绕过手法已广播] guard=%s → %s（全项目 miner 可查复用）" % (args.guard, args.technique))


def cmd_add_payload(paths, args):
    doc = load(paths)
    doc.setdefault("payloads", []).append({
        "vuln_type": args.vuln_type, "payload": args.payload,
        "context": args.context or "", "success": bool(args.success), "at": c.now_iso(),
    })
    save(paths, doc)
    print("[payload] 已登记（%s）" % ("有效" if args.success else "无效"))


def cmd_query(paths, args):
    """子代理开挖前查询：该 host 已知 WAF/绕过手法 + 全局有效 payload。"""
    doc = load(paths)
    hits = [w for w in doc.get("waf", []) if not args.host or w.get("host") == args.host]
    if hits:
        print("[已知 WAF]")
        for w in hits:
            print("  - %s | %s | %s" % (w.get("host"), w.get("fingerprint"), w.get("note", "")))
    bps = [b for b in doc.get("bypasses", [])
           if not args.host or not b.get("host") or b.get("host") == args.host]
    if args.guard:
        bps = [b for b in bps if args.guard in (b.get("guard") or "")]
    if bps:
        print("[可复用绕过手法]")
        for b in bps:
            print("  - guard=%s → %s（%s）" % (b.get("guard"), b.get("technique"), b.get("evidence", "")[:80]))
    good = [p for p in doc.get("payloads", []) if p.get("success")]
    if good:
        print("[已验证 payload] %d 条（按漏洞类查用）" % len(good))
    if not (hits or bps or good):
        print("[无情报] 该 host 暂无共享情报")


def cmd_export_global(paths, data_root):
    """项目结束：有效手法沉淀到全局记忆（memory-global/）。"""
    doc = load(paths)
    gdir = c.memory_global_dir(data_root)
    os.makedirs(gdir, exist_ok=True)
    gfile = os.path.join(gdir, "waf-bypass.json")
    gdoc = c.load_json(gfile, default={"_note": "全局 WAF/绕过手法沉淀", "entries": []})
    n = 0
    for b in doc.get("bypasses", []):
        key = (b.get("guard"), b.get("technique"))
        if not any((e.get("guard"), e.get("technique")) == key for e in gdoc["entries"]):
            gdoc["entries"].append(dict(b, project=paths["dir"]))
            n += 1
    for w in doc.get("waf", []):
        key = ("waf", w.get("host"), w.get("fingerprint"))
        if not any((e.get("kind"), e.get("host"), e.get("fingerprint")) == key
                   for e in gdoc["entries"] if e.get("kind") == "waf"):
            gdoc["entries"].append(dict(w, kind="waf", project=paths["dir"]))
            n += 1
    c.atomic_write_json(gfile, gdoc)
    print("[沉淀] 全局记忆新增 %d 条 → %s" % (n, gfile))


def cmd_import_global(paths, data_root):
    """开挖前预热：全局记忆中的手法并入本项目共享情报。"""
    gfile = os.path.join(c.memory_global_dir(data_root), "waf-bypass.json")
    gdoc = c.load_json(gfile, default=None)
    if not gdoc:
        print("[预热] 全局记忆为空，跳过")
        return
    doc = load(paths)
    n = 0
    for e in gdoc.get("entries", []):
        if e.get("kind") == "waf":
            continue
        key = (e.get("guard"), e.get("technique"))
        if not any((b.get("guard"), b.get("technique")) == key for b in doc.get("bypasses", [])):
            doc.setdefault("bypasses", []).append(
                {"host": "", "guard": e.get("guard"), "technique": e.get("technique"),
                 "evidence": "全局记忆沉淀（源自 %s）" % e.get("project", ""), "at": c.now_iso()})
            n += 1
    save(paths, doc)
    print("[预热] 从全局记忆并入 %d 条绕过手法" % n)


def main():
    p = argparse.ArgumentParser(description="DeepBounty 项目级共享情报库")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("show")
    pw = sub.add_parser("add-waf")
    pw.add_argument("--host", required=True)
    pw.add_argument("--fingerprint", required=True)
    pw.add_argument("--note", default="")
    pb = sub.add_parser("add-bypass")
    pb.add_argument("--host", default="")
    pb.add_argument("--guard", required=True)
    pb.add_argument("--technique", required=True)
    pb.add_argument("--evidence", default="")
    pb.add_argument("--by", default="")
    pp = sub.add_parser("add-payload")
    pp.add_argument("--vuln-type", dest="vuln_type", required=True)
    pp.add_argument("--payload", required=True)
    pp.add_argument("--context", default="")
    pp.add_argument("--success", action="store_true")
    pq = sub.add_parser("query")
    pq.add_argument("--host", default="")
    pq.add_argument("--guard", default="")
    sub.add_parser("export-global")
    sub.add_parser("import-global")
    args = p.parse_args()

    paths = c.project_paths(args.data_root, args.project)
    if args.cmd == "show":
        cmd_show(paths)
    elif args.cmd == "add-waf":
        cmd_add_waf(paths, args)
    elif args.cmd == "add-bypass":
        cmd_add_bypass(paths, args)
    elif args.cmd == "add-payload":
        cmd_add_payload(paths, args)
    elif args.cmd == "query":
        cmd_query(paths, args)
    elif args.cmd == "export-global":
        cmd_export_global(paths, args.data_root)
    elif args.cmd == "import-global":
        cmd_import_global(paths, args.data_root)


if __name__ == "__main__":
    main()
