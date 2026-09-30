# -*- coding: utf-8 -*-
"""DeepBounty 通杀复用引擎（pattern replay，借 AutoHunter 一打一片）。

确认一个漏洞 → 提取模式（漏洞类×参数名×payload×信号特征×端点指纹）→
同项目/跨项目同指纹接口批量验证。修 tyang-skill2 "一洞一挖、同类接口重复交学费"。

模式文件：项目级 memory/patterns.json；复盘时沉淀全局 memory-global/vuln-patterns.json。
idor-params-hit 统计：stats 子命令聚合全局模式命中，供新项目记忆预热。

用法：
    python pattern_replay.py --project <id> extract --url-id URL00012 --param id --vuln-type SQL注入 \
        --payload "' AND SLEEP(5)-- -" --signal-type time --signal-value 5000
    python pattern_replay.py --project <id> candidates --pattern-id PAT-xxxxxxxx
    python pattern_replay.py --project <id> replay --pattern-id PAT-xxxxxxxx [--dry-run] [--limit 20]
    python pattern_replay.py --project <id> stats
"""

import argparse
import hashlib
import os
import re
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c
import cred_vault as vault
import authz_probe as az


def patterns_file(paths):
    return os.path.join(paths["memory_dir"], "patterns.json")


def load_patterns(paths):
    return c.load_json(patterns_file(paths), default={"_note": "通杀模式库", "patterns": []})


def save_patterns(paths, doc):
    c.atomic_write_json(patterns_file(paths), doc)


def _pid(vuln_type, param, payload):
    raw = "%s|%s|%s" % (vuln_type, param, payload)
    return "PAT-" + hashlib.md5(raw.encode("utf-8")).hexdigest()[:8]


# ---------- extract ----------

def cmd_extract(paths, args, data_root):
    caps = c.load_json(paths["endpoint_caps"], default={}).get("endpoints", [])
    cap = next((e for e in caps if e.get("url_id") == args.url_id), {})
    fp = {
        "content_types": cap.get("content_types", []),
        "has_json": cap.get("has_json", False),
        "auth_seen": cap.get("auth_seen", True),
        "param_source": "",
    }
    for p in cap.get("params", []):
        if (p.get("name") or "") == args.param:
            fp["param_source"] = p.get("source") or ""
    pat = {
        "pattern_id": _pid(args.vuln_type, args.param, args.payload),
        "vuln_type": args.vuln_type,
        "param_name": args.param,
        "payload": args.payload,
        "signal": {"type": args.signal_type, "value": args.signal_value},
        "fingerprint": fp,
        "source": {"project": paths["dir"], "url_id": args.url_id,
                   "report_id": args.report_id or ""},
        "hits": 0, "misses": 0,
        "created": c.now_iso(),
    }
    doc = load_patterns(paths)
    if any(p["pattern_id"] == pat["pattern_id"] for p in doc["patterns"]):
        print("[已存在] %s" % pat["pattern_id"])
        return pat["pattern_id"]
    doc["patterns"].append(pat)
    save_patterns(paths, doc)
    print("[模式已提取] %s | %s × 参数 %s" % (pat["pattern_id"], args.vuln_type, args.param))

    # 同步沉淀全局记忆（通杀的核心：跨项目复用）
    gdir = c.memory_global_dir(data_root)
    os.makedirs(gdir, exist_ok=True)
    gfile = os.path.join(gdir, "vuln-patterns.json")
    gdoc = c.load_json(gfile, default={"_note": "全局漏洞模式库（通杀复用）", "patterns": []})
    if not any(p["pattern_id"] == pat["pattern_id"] for p in gdoc["patterns"]):
        gdoc["patterns"].append(pat)
        c.atomic_write_json(gfile, gdoc)
        print("[全局沉淀] → %s" % gfile)
    return pat["pattern_id"]


# ---------- candidates ----------

def _same_param_name(a, b):
    a, b = (a or "").lower(), (b or "").lower()
    return a == b or a.split(".")[-1] == b.split(".")[-1]


def find_candidates(paths, pat):
    caps = c.load_json(paths["endpoint_caps"], default={}).get("endpoints", [])
    out = []
    for e in caps:
        if pat["vuln_type"] not in (e.get("applicable") or {}):
            continue
        for p in e.get("params", []):
            if not _same_param_name(p.get("name"), pat["param_name"]):
                continue
            # 已 confirmed 的同参数同类跳过
            mf = os.path.join(paths["vuln_matrix_dir"], "%s.json" % e["url_id"])
            matrix = c.load_json(mf, default={}) or {}
            done = any(
                ent.get("vuln_type") == pat["vuln_type"] and ent.get("status") == "found"
                for ent in (matrix.get("params") or {}).get(p.get("name"), []) or [])
            if not done:
                out.append({"url_id": e["url_id"], "url": e["url"], "host": e["host"],
                            "param": p.get("name")})
            break
    return out


def cmd_candidates(paths, args):
    doc = load_patterns(paths)
    pat = next((p for p in doc["patterns"] if p["pattern_id"] == args.pattern_id), None)
    if not pat:
        print("[错误] 模式不存在：%s" % args.pattern_id)
        sys.exit(1)
    cands = find_candidates(paths, pat)
    print("[候选] 模式 %s（%s × %s）→ 同指纹未确认接口 %d 个"
          % (pat["pattern_id"], pat["vuln_type"], pat["param_name"], len(cands)))
    for cd in cands:
        print("  - %s %s (param=%s)" % (cd["url_id"], cd["url"], cd["param"]))
    return cands


# ---------- replay ----------

def detect_signal(pat, status, body, elapsed_ms):
    sig = pat.get("signal") or {}
    st, sv = sig.get("type"), str(sig.get("value") or "")
    if st == "keyword" and sv:
        return sv in (body or "")
    if st == "status" and sv.isdigit():
        return status == int(sv)
    if st == "time" and sv.replace(".", "", 1).isdigit():
        return elapsed_ms >= float(sv)
    return False


def cmd_replay(paths, args, data_root):
    doc = load_patterns(paths)
    pat = next((p for p in doc["patterns"] if p["pattern_id"] == args.pattern_id), None)
    if not pat:
        print("[错误] 模式不存在：%s" % args.pattern_id)
        sys.exit(1)
    cands = find_candidates(paths, pat)[: args.limit]
    if args.dry_run:
        print("[dry-run] 将对 %d 个候选重放 payload：%s" % (len(cands), pat["payload"][:80]))
        for cd in cands:
            print("  - %s %s" % (cd["url_id"], cd["url"]))
        return

    cfg = c.load_json(paths["config"], default={}) or {}
    proxy = "http://127.0.0.1:%s" % cfg.get("proxy_port", 24304)
    cov = c.load_json(os.path.join(paths["cred_dir"], "coverage.json"), default={}) or {}
    sess_by_id = {s["cred_id"]: s for s in vault.load_sessions(paths).get("sessions", [])}

    results = []
    hits = 0
    for cd in cands:
        uid, pname = cd["url_id"], cd["param"]
        tpl = az.parse_original_request(paths, uid)
        if not tpl:
            results.append({"url_id": uid, "param": pname, "result": "no_template"})
            continue
        cred_ids = ((cov.get("hosts") or {}).get(cd["host"]) or {}).get("alive_cred_ids") or []
        sess = next((sess_by_id[cid] for cid in cred_ids if cid in sess_by_id), None)
        body2 = az.swap_body_param(tpl.get("body", ""), pname, pat["payload"])
        url2 = az.swap_url_param(tpl["url"], pname, pat["payload"])
        tpl2 = dict(tpl, url=url2, body=body2)
        t0 = time.time()
        status, _, body, cred_id = az.fetch(tpl2, sess, proxy=proxy)
        elapsed = (time.time() - t0) * 1000
        hit = detect_signal(pat, status, body, elapsed)
        results.append({"url_id": uid, "param": pname, "cred_id": cred_id,
                        "status": status, "elapsed_ms": int(elapsed),
                        "result": "hit" if hit else "miss"})
        if hit:
            hits += 1
            print("[命中] %s %s param=%s（%s）——调度 miner 坐实"
                  % (uid, cd["url"], pname, pat["vuln_type"]))
    pat["hits"] = pat.get("hits", 0) + hits
    pat["misses"] = pat.get("misses", 0) + (len(results) - hits)
    save_patterns(paths, doc)
    rfile = os.path.join(paths["memory_dir"], "replay-%s.json" % pat["pattern_id"])
    c.atomic_write_json(rfile, {"pattern": pat, "results": results, "at": c.now_iso()})
    print("[完成] 重放 %d 个候选，命中 %d → %s" % (len(results), hits, rfile))
    if hits:
        print("[下一步] 命中项由 miner 按要点坐实（过 SRC 报告门才 found），勿直接入账")


# ---------- stats（idor-params-hit 式统计） ----------

def cmd_stats(paths, data_root):
    gfile = os.path.join(c.memory_global_dir(data_root), "vuln-patterns.json")
    gdoc = c.load_json(gfile, default={"patterns": []})
    agg = {}
    for p in gdoc.get("patterns", []):
        key = (p.get("vuln_type"), (p.get("param_name") or "").lower())
        a = agg.setdefault(key, {"patterns": 0, "hits": 0, "misses": 0})
        a["patterns"] += 1
        a["hits"] += p.get("hits", 0)
        a["misses"] += p.get("misses", 0)
    print("[全局模式命中统计]（idor-params-hit 式，供记忆预热优先排序）")
    for (vt, pn), a in sorted(agg.items(), key=lambda kv: -kv[1]["hits"]):
        total = a["hits"] + a["misses"]
        rate = (a["hits"] * 100 // total) if total else 0
        print("  %-14s param=%-16s 模式 %d 个 | 重放命中 %d/%d（%d%%）"
              % (vt, pn, a["patterns"], a["hits"], total, rate))
    # 落盘 idor-params-hit.json 供 miner 预热直读
    hfile = os.path.join(c.memory_global_dir(data_root), "idor-params-hit.json")
    c.atomic_write_json(hfile, {
        "_note": "参数×漏洞类历史命中统计（pattern_replay stats 生成）",
        "stats": [{"vuln_type": k[0], "param": k[1], **v} for k, v in agg.items()],
        "updated": c.now_iso()})


def main():
    p = argparse.ArgumentParser(description="DeepBounty 通杀复用引擎")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    sub = p.add_subparsers(dest="cmd", required=True)
    pe = sub.add_parser("extract")
    pe.add_argument("--url-id", dest="url_id", required=True)
    pe.add_argument("--param", required=True)
    pe.add_argument("--vuln-type", dest="vuln_type", required=True)
    pe.add_argument("--payload", required=True)
    pe.add_argument("--signal-type", dest="signal_type",
                    choices=["keyword", "status", "time"], default="keyword")
    pe.add_argument("--signal-value", dest="signal_value", required=True)
    pe.add_argument("--report-id", dest="report_id", default="")
    pc = sub.add_parser("candidates")
    pc.add_argument("--pattern-id", dest="pattern_id", required=True)
    pr = sub.add_parser("replay")
    pr.add_argument("--pattern-id", dest="pattern_id", required=True)
    pr.add_argument("--dry-run", dest="dry_run", action="store_true")
    pr.add_argument("--limit", type=int, default=20)
    sub.add_parser("stats")
    args = p.parse_args()

    paths = c.project_paths(args.data_root, args.project)
    if args.cmd == "extract":
        cmd_extract(paths, args, args.data_root)
    elif args.cmd == "candidates":
        cmd_candidates(paths, args)
    elif args.cmd == "replay":
        cmd_replay(paths, args, args.data_root)
    elif args.cmd == "stats":
        cmd_stats(paths, args.data_root)


if __name__ == "__main__":
    main()
