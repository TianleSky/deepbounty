# -*- coding: utf-8 -*-
"""DeepBounty 任务树：Project→Host→Endpoint→(Param×VulnClass) 四级叶子调度与状态机。

借 PentestGPT 任务树 + Argus 叶子预算。叶子是调度最小单元；vuln-matrix/{URLID}.json
仍是逐参数证据账本（miner 写），本文件是调度状态层（check_mining.py 交叉核对两者）。

叶子状态机：pending → probing → signal → exploiting → confirmed / filtered / exhausted / blocked
- confirmed：矩阵 found + 过 SRC 报告门 + 盲验证通过
- filtered：有信号有防护，等 bypass（绕过后转 confirmed 或 exhausted）
- exhausted：终结未检出，必须带 death_cause（DEATH_CAUSE 枚举）+ 满足证据标准（evidence_gate）
- blocked：客观阻塞（无凭据/边界禁止/前置不满足），必须带 death_cause + notes

用法：
    python task_tree.py --project <id> build            # 从 capability 矩阵建树（幂等，只增不改状态）
    python task_tree.py --project <id> status           # 状态汇总
    python task_tree.py --project <id> next [--n 20]    # untested-first：取下一批待测叶子（按 URL 分组）
    python task_tree.py --project <id> update --leaf "URL00001|id|SQL注入" --status signal [--cred CRED0001] [--note ...]
    python task_tree.py --project <id> sync             # 从 vuln-matrix 回同步叶子终态
"""

import argparse
import os
import sys
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c

TERMINAL = {"confirmed", "filtered", "exhausted", "blocked"}


def load_tree(paths):
    return c.load_json(paths["task_tree"], default=None)


def save_tree(paths, tree):
    tree["updated"] = c.now_iso()
    c.atomic_write_json(paths["task_tree"], tree)


def leaf_id(url_id, param, vuln_type):
    return "%s|%s|%s" % (url_id, param, vuln_type)


def cmd_build(paths):
    caps = c.load_json(paths["endpoint_caps"], default=None)
    if caps is None:
        print("[错误] 未找到 endpoint-capabilities.json，先跑 capability_matrix.py")
        sys.exit(1)
    cov = c.load_json(os.path.join(paths["cred_dir"], "coverage.json"), default={}) or {}
    authz_blocked = bool(cov.get("authz_blocked"))

    tree = load_tree(paths) or {
        "_note": "DeepBounty 任务树（调度状态层；证据账本在 vuln-matrix/）",
        "leaves": [], "created": c.now_iso(),
    }
    existing = {l["leaf_id"]: l for l in tree.get("leaves", [])}
    n_new = 0
    for ep in caps.get("endpoints", []):
        uid = ep["url_id"]
        params = [p.get("name") for p in ep.get("params", []) if p.get("name")]
        for vt, cat in (ep.get("applicable") or {}).items():
            # 越权/IDOR 同时是 URL 级（未授权面）与参数级（ID 遍历）
            targets = list(params) if params else ["_url_level"]
            if vt in ("越权", "敏感信息泄露", "CORS") and "_url_level" not in targets:
                targets.append("_url_level")
            for pname in targets:
                lid = leaf_id(uid, pname, vt)
                if lid in existing:
                    continue
                status = "pending"
                note = ""
                if authz_blocked and vt in ("越权", "IDOR"):
                    status = "blocked"
                    note = "无双账号（cred_gate authz_blocked）：禁止记 tested_not_found，补账号后重置 pending"
                existing[lid] = {
                    "leaf_id": lid, "url_id": uid, "url": ep.get("url", ""),
                    "host": ep.get("host", ""), "param": pname, "vuln_type": vt,
                    "category": cat, "status": status,
                    "probe_count": 0, "cred_id": "", "death_cause": "",
                    "evidence": "", "notes": note,
                    "created": c.now_iso(), "updated": c.now_iso(),
                }
                n_new += 1
    tree["leaves"] = sorted(existing.values(), key=lambda l: l["leaf_id"])
    save_tree(paths, tree)
    print("[建树] 叶子总数 %d（本次新增 %d）；authz_blocked=%s"
          % (len(tree["leaves"]), n_new, authz_blocked))


def cmd_status(paths):
    tree = load_tree(paths)
    if not tree:
        print("[提示] 任务树不存在，先 build")
        return
    stat = {}
    for l in tree.get("leaves", []):
        stat[l["status"]] = stat.get(l["status"], 0) + 1
    total = len(tree.get("leaves", []))
    done = sum(stat.get(s, 0) for s in TERMINAL)
    print("[任务树] 叶子 %d | 终态 %d (%.0f%%)" % (total, done, 100.0 * done / max(total, 1)))
    for s in ("pending", "probing", "signal", "exploiting",
              "confirmed", "filtered", "exhausted", "blocked"):
        if stat.get(s):
            print("       %-10s %d" % (s, stat[s]))


def cmd_next(paths, n):
    """untested-first：pending 优先，其次 probing/signal（中断恢复）。"""
    tree = load_tree(paths)
    if not tree:
        print("[提示] 任务树不存在，先 build")
        return
    leaves = tree.get("leaves", [])
    pend = [l for l in leaves if l["status"] == "pending"]
    resum = [l for l in leaves if l["status"] in ("probing", "signal", "exploiting")]
    batch = (pend + resum)[:n]
    by_url = {}
    for l in batch:
        by_url.setdefault(l["url_id"], []).append(l)
    for uid, ls in sorted(by_url.items()):
        print("%s (%s)" % (uid, ls[0]["url"]))
        for l in ls:
            print("    %-24s %-16s [%s]" % (l["param"], l["vuln_type"], l["status"]))
    print("[批次] %d 个叶子 / %d 个 URL（剩余 pending %d）" % (len(batch), len(by_url), len(pend)))


def cmd_update(paths, args):
    tree = load_tree(paths)
    if not tree:
        print("[错误] 任务树不存在")
        sys.exit(1)
    leaf = next((l for l in tree.get("leaves", []) if l["leaf_id"] == args.leaf), None)
    if leaf is None:
        print("[错误] 叶子不存在：%s" % args.leaf)
        sys.exit(1)
    if args.status not in c.LEAF_STATUS:
        print("[错误] status 须 ∈ %s" % sorted(c.LEAF_STATUS))
        sys.exit(1)
    if args.status in ("exhausted", "blocked"):
        if args.death_cause not in c.DEATH_CAUSE:
            print("[错误] %s 必须带 --death-cause ∈ %s" % (args.status, sorted(c.DEATH_CAUSE)))
            sys.exit(1)
        leaf["death_cause"] = args.death_cause
    if args.status == "exhausted" and not (args.note or "").strip():
        print("[错误] exhausted 必须带 --note 说明已试内容与判无依据")
        sys.exit(1)
    leaf["status"] = args.status
    if args.cred:
        leaf["cred_id"] = args.cred
    if args.note:
        leaf["notes"] = args.note
    if args.probes is not None:
        leaf["probe_count"] = args.probes
    leaf["updated"] = c.now_iso()
    save_tree(paths, tree)
    print("[更新] %s → %s" % (args.leaf, args.status))


def cmd_sync(paths):
    """从 vuln-matrix 回同步叶子终态（miner 写矩阵后调用）。"""
    tree = load_tree(paths)
    if not tree:
        print("[错误] 任务树不存在")
        sys.exit(1)
    by_leaf = {l["leaf_id"]: l for l in tree.get("leaves", [])}
    n_sync = 0
    for fn in os.listdir(paths["vuln_matrix_dir"]) if os.path.isdir(paths["vuln_matrix_dir"]) else []:
        if not fn.endswith(".json"):
            continue
        uid = fn[:-5]
        matrix = c.load_json(os.path.join(paths["vuln_matrix_dir"], fn), default={}) or {}
        entries = []
        for pname, ents in (matrix.get("params") or {}).items():
            for e in ents or []:
                entries.append((pname, e))
        for e in matrix.get("_url_level", []) or []:
            entries.append(("_url_level", e))
        for pname, e in entries:
            lid = leaf_id(uid, pname, e.get("vuln_type", ""))
            leaf = by_leaf.get(lid)
            if leaf is None:
                continue
            st = e.get("status")
            mapped = {"found": "confirmed", "filtered": "filtered",
                      "tested_not_found": "exhausted", "doubtful": "blocked"}.get(st)
            if mapped and leaf["status"] != "confirmed":  # confirmed 不降级
                if leaf["status"] != mapped:
                    leaf["status"] = mapped
                    n_sync += 1
                if e.get("cred_id"):
                    leaf["cred_id"] = e["cred_id"]
                if isinstance(e.get("probe_count"), int):
                    leaf["probe_count"] = e["probe_count"]
                leaf["updated"] = c.now_iso()
    save_tree(paths, tree)
    print("[同步] 从矩阵回同步叶子 %d 个" % n_sync)


def main():
    p = argparse.ArgumentParser(description="DeepBounty 任务树（四级叶子调度）")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build")
    sub.add_parser("status")
    pn = sub.add_parser("next")
    pn.add_argument("--n", type=int, default=20)
    pu = sub.add_parser("update")
    pu.add_argument("--leaf", required=True)
    pu.add_argument("--status", required=True)
    pu.add_argument("--cred", default="")
    pu.add_argument("--note", default="")
    pu.add_argument("--death-cause", dest="death_cause", default="")
    pu.add_argument("--probes", type=int, default=None)
    sub.add_parser("sync")
    args = p.parse_args()

    paths = c.project_paths(args.data_root, args.project)
    if args.cmd == "build":
        cmd_build(paths)
    elif args.cmd == "status":
        cmd_status(paths)
    elif args.cmd == "next":
        cmd_next(paths, args.n)
    elif args.cmd == "update":
        cmd_update(paths, args)
    elif args.cmd == "sync":
        cmd_sync(paths)


if __name__ == "__main__":
    main()
