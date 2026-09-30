# -*- coding: utf-8 -*-
"""DeepBounty 挖掘前凭据硬门禁（cred gate）：未验活不得消费、无 alive 身份不得开挖、
越权类无双账号记 blocked（不许记 tested_not_found）。

检查项（硬错误 → state.json.gates.cred_gate，blocking_count==0 才放行进入挖掘）：
1. [身份覆盖] 任务范围内每个 host 至少 1 个 alive 且非匿名的身份（host 绑定或全局身份）。
   —— 修 tyang-skill2 "aliyun 挖掘期 70% 请求无凭据"。
2. [验活前置] 不存在 status=unknown 的非匿名身份（必须全部经 cred_verify 判定）。
   —— 修 "344 个身份从未验活却 success"。
3. [双账号就绪] 若挖掘范围含 AUTHZ 类（越权/IDOR）：至少一个 host 有 ≥2 个 alive、
   不同 account_id、同 privilege 层级的身份（attacker+victim 或两个 user）。
   不满足不阻断整个挖掘，但 AUTHZ 叶子一律记 blocked（由 task_tree 读取 coverage 执行）。
4. [凭据追溯] 输出 cred/coverage.json：每 host 的可用 cred_id 列表（miner 取证用）。

用法：
    python cred_gate.py --project <id> [--data-root pentest-data]
"""

import argparse
import os
import sys
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c
import cred_vault as vault


def _host_of(url):
    try:
        return (urlsplit(url).hostname or "").lower()
    except Exception:
        return ""


def main():
    p = argparse.ArgumentParser(description="DeepBounty 挖掘前凭据硬门禁")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    args = p.parse_args()

    paths = c.project_paths(args.data_root, args.project)
    sess_doc = vault.load_sessions(paths)
    sessions = sess_doc.get("sessions", [])
    inv = c.load_json(paths["inventory"], default={}) or {}

    # 任务范围 host 集合（URL 清单 page/api）
    hosts = sorted({_host_of(u.get("url", "")) for u in inv.get("urls", [])
                    if u.get("category") in ("page", "api")} - {""})

    alive = [s for s in sessions if s.get("status") == "alive" and not s.get("is_anonymous")]
    unknown = [s for s in sessions if s.get("status") == "unknown" and not s.get("is_anonymous")]

    errors, reviews = [], []

    # 1. 身份覆盖
    coverage = {}
    for h in hosts:
        creds = [s for s in alive if h in (s.get("hosts") or [])]
        if not creds:  # 无 host 绑定的全局身份兜底
            creds = [s for s in alive if not s.get("hosts")]
        coverage[h] = {
            "alive_cred_ids": [s["cred_id"] for s in creds],
            "roles": sorted({s.get("role", "") for s in creds}),
            "account_ids": sorted({s.get("account_id", "") for s in creds if s.get("account_id")}),
        }
        if not creds:
            errors.append("[身份覆盖] host %s 无任何 alive 非匿名身份：该 host 接口不得开挖。"
                          "先 cred_vault 补凭据 + cred_verify 验活，或调度 deepbounty-cred-steward" % h)

    # 2. 验活前置
    for s in unknown:
        errors.append("[验活前置] %s (role=%s user=%s) status=unknown 未验活："
                      "运行 cred_verify.py --write 判定后才可消费" %
                      (s.get("cred_id"), s.get("role"), s.get("username") or "-"))

    # 3. 双账号就绪（AUTHZ 前提）
    dual_ready_hosts = []
    for h in hosts:
        cov = coverage.get(h) or {}
        if len(cov.get("account_ids", [])) >= 2:
            dual_ready_hosts.append(h)
    authz_blocked = len(dual_ready_hosts) == 0 and len(hosts) > 0
    if authz_blocked:
        reviews.append("[双账号就绪] 无任何 host 具备 ≥2 个 alive 不同账号 → AUTHZ(越权/IDOR) 叶子"
                       "一律记 blocked（禁止记 tested_not_found）；补第二个测试账号后重跑本门禁")

    # 4. 匿名身份提示
    anon = [s for s in sessions if s.get("is_anonymous")]
    if anon:
        reviews.append("[匿名凭据] %d 个匿名/设备指纹凭据仅作未登录基线，不计入身份覆盖" % len(anon))

    cov_doc = {
        "_note": "凭据覆盖（cred_gate 产出；miner 取 cred_id 消费，矩阵条目强制 cred_id 追溯）",
        "hosts": coverage,
        "dual_account_ready_hosts": dual_ready_hosts,
        "authz_blocked": authz_blocked,
        "generated": c.now_iso(),
    }
    c.atomic_write_json(os.path.join(paths["cred_dir"], "coverage.json"), cov_doc)

    blocking = c.emit_gate_result(paths, "cred_gate", errors, reviews)
    print("[覆盖] host %d 台；有 alive 身份 %d 台；双账号就绪 %d 台"
          % (len(hosts), sum(1 for h in hosts if coverage[h]["alive_cred_ids"]),
             len(dual_ready_hosts)))
    sys.exit(1 if blocking else 0)


if __name__ == "__main__":
    main()
