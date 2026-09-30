# -*- coding: utf-8 -*-
"""DeepBounty 总门禁（check mining）：挖掘阶段收尾的一站式硬校验 + 深度指标。

串起所有子门禁并加 DeepBounty 特有的深度指标（修 tyang-skill2 三轮审计断点）：
1. [凭据前置] cred/coverage.json 存在；挖掘涉及的 host 均有 ≥1 alive 身份（cred_gate 产物）；
2. [挖掘门禁] check_vuln_mining.py（覆盖度/矩阵合规/报告登记）；
3. [证据门禁] evidence_gate.py（tested_not_found 深度/filtered 举证/报告零脱敏/C 类硬拦/凭据追溯）；
4. [检查点门禁] checkpoint_gate.py（机读检查点全集 ↔ checkpoints.md 自校验 + 矩阵全覆盖）；
5. [任务树一致] task-tree.json 叶子状态与矩阵条目一致（sync 后无漂移）；
6. [深度指标] 覆盖率 / 凭据追溯率 / filtered 占比 / 平均探测深度——低于阈值为硬错误或复核。

退出码：0=全部通过（仍有 AI 复核项），1=有硬错误。
用法：
    python check_mining.py --project <id> [--data-root pentest-data] [--ack "<理由>"]
"""

import argparse
import glob
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c
import evidence_gate

# 深度指标阈值
MIN_CRED_TRACE_RATE = 0.95      # 终态条目 cred_id 追溯率 ≥95%（修 0/38997 追溯）
MAX_FILTERED_RATIO = 0.50       # filtered 占信号条目比 >50% 说明 bypass 阶段未尽职（复核项）
MIN_AVG_PROBE = 2.0             # 终态条目平均 probe_count <2 说明探测太浅（复核项）


def _run(script, project, data_root):
    return subprocess.run(
        [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), script),
         "--project", project, "--data-root", data_root],
        capture_output=True, text=True, encoding="utf-8", errors="replace")


def check_cred_precondition(paths, errors):
    cov_file = os.path.join(paths["cred_dir"], "coverage.json")
    cov = c.load_json(cov_file, default=None)
    if cov is None:
        errors.append("[凭据前置] 未找到 cred/coverage.json——挖掘前必须过 cred_gate.py（硬门禁）")
        return
    # cred_gate 是凭据唯一权威：其 blocking_count==0（含有效 acknowledged 裁决）即前置已过，
    # 此处只防"完全没跑过 cred_gate"，不再对逐 host 原始 alive 重复裁决（否则架空 acknowledged 出口）。
    st = c.load_json(paths["state"], default={}) or {}
    cg = (st.get("gates", {}) or {}).get("cred_gate", {}) or {}
    if cg.get("blocking_count") == 0 and cg.get("checked_at"):
        return
    hosts = cov.get("hosts") or {}
    no_cred = [h for h, d in hosts.items()
               if not d.get("alive_cred_ids") and not d.get("anon_baseline")]
    for h in no_cred:
        errors.append("[凭据前置] host %s 无 alive 非匿名身份——cred_gate 未通过，禁止收尾" % h)


def check_tree_consistency(paths, errors, reviews):
    tree = c.load_json(paths["task_tree"], default=None)
    if tree is None:
        reviews.append("[复核] 无 task-tree.json（旧项目或未建树）——跳过任务树一致性核查")
        return
    leaves = tree.get("leaves", [])
    if not leaves:
        return
    pending = [l for l in leaves if l.get("status") in ("pending", "probing", "signal", "exploiting")]
    if pending:
        errors.append("[任务树] 仍有 %d 个叶子未达终态（pending/probing/signal/exploiting）——"
                      "先跑 task_tree.py sync 并补测" % len(pending))
    # 矩阵 found 但树未 confirmed（sync 未跑）
    n_drift = 0
    by_leaf = {l["leaf_id"]: l for l in leaves}
    import task_tree as tt
    for fp in glob.glob(os.path.join(paths["vuln_matrix_dir"], "*.json")):
        uid = os.path.splitext(os.path.basename(fp))[0]
        matrix = c.load_json(fp, default={}) or {}
        for pname, ents in (matrix.get("params") or {}).items():
            for e in ents or []:
                if e.get("status") == "found":
                    lid = tt.leaf_id(uid, pname, e.get("vuln_type", ""))
                    leaf = by_leaf.get(lid)
                    if leaf and leaf.get("status") != "confirmed":
                        n_drift += 1
    if n_drift:
        errors.append("[任务树] %d 个矩阵 found 条目对应叶子非 confirmed——跑 task_tree.py sync" % n_drift)


def depth_metrics(paths, errors, reviews):
    """深度指标统计与阈值校验。"""
    total = with_cred = filtered = signal_total = 0
    probe_sum, probe_n = 0, 0
    for fp in glob.glob(os.path.join(paths["vuln_matrix_dir"], "*.json")):
        matrix = c.load_json(fp, default={}) or {}
        entries = []
        for pname, ents in (matrix.get("params") or {}).items():
            for e in ents or []:
                entries.append(e)
        entries.extend(matrix.get("_url_level", []) or [])
        for e in entries:
            st = e.get("status")
            if st not in ("found", "tested_not_found", "doubtful", "filtered"):
                continue
            total += 1
            if e.get("cred_id"):
                with_cred += 1
            if st == "filtered":
                filtered += 1
                signal_total += 1
            elif st == "found":
                signal_total += 1
            pc = e.get("probe_count")
            if isinstance(pc, int) and pc > 0:
                probe_sum += pc
                probe_n += 1
    if not total:
        errors.append("[深度] 矩阵无任何终态条目——挖掘未开始")
        return
    trace_rate = with_cred / total
    avg_probe = probe_sum / probe_n if probe_n else 0
    filtered_ratio = filtered / signal_total if signal_total else 0
    print("")
    print("==== 深度指标 ====")
    print("终态条目 %d | 凭据追溯率 %.1f%%（≥%.0f%%） | 平均探测深度 %.1f 发 | filtered 占信号比 %.1f%%（%d/%d）"
          % (total, trace_rate * 100, MIN_CRED_TRACE_RATE * 100, avg_probe,
             filtered_ratio * 100, filtered, signal_total))
    if trace_rate < MIN_CRED_TRACE_RATE:
        errors.append("[深度] 凭据追溯率 %.1f%% < %.0f%%——终态条目必须带 cred_id（修挖掘期裸奔）"
                      % (trace_rate * 100, MIN_CRED_TRACE_RATE * 100))
    if avg_probe < MIN_AVG_PROBE:
        reviews.append("[复核] 平均探测深度 %.1f 发 < %.0f——整体探测偏浅，请 AI 抽查代表性条目"
                       % (avg_probe, MIN_AVG_PROBE))
    if filtered_ratio > MAX_FILTERED_RATIO:
        reviews.append("[复核] filtered 占信号比 %.1f%% > %.0f%%——大量条目卡在防护，"
                       "确认 deepbounty-bypass 已逐条处理（≥3 族）" % (filtered_ratio * 100, MAX_FILTERED_RATIO * 100))


def main():
    p = argparse.ArgumentParser(description="DeepBounty 总门禁（收尾一站式硬校验）")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    args = p.parse_args()

    paths = c.project_paths(args.data_root, args.project)
    errors, reviews = [], []

    print("==== [1/6] 凭据前置（cred_gate 产物）====")
    check_cred_precondition(paths, errors)
    print("OK" if not errors else "见硬错误")

    print("==== [2/6] 挖掘门禁（check_vuln_mining）====")
    r = _run("check_vuln_mining.py", args.project, args.data_root)
    print((r.stdout or "")[-3000:])
    if r.returncode != 0:
        errors.append("[挖掘门禁] check_vuln_mining.py 未通过（详见上方输出）")

    print("==== [3/6] 证据门禁（evidence_gate）====")
    eg_errors, eg_reviews = evidence_gate.run_all(paths)
    errors.extend(eg_errors)
    reviews.extend(eg_reviews)
    print("硬错误 %d / 复核 %d" % (len(eg_errors), len(eg_reviews)))

    print("==== [4/6] 检查点门禁（checkpoint_gate）====")
    r = _run("checkpoint_gate.py", args.project, args.data_root)
    print((r.stdout or "")[-2000:])
    if r.returncode != 0:
        errors.append("[检查点门禁] checkpoint_gate.py 未通过（详见上方输出）")

    print("==== [5/6] 任务树一致性 ====")
    check_tree_consistency(paths, errors, reviews)

    print("==== [6/6] 深度指标 ====")
    depth_metrics(paths, errors, reviews)

    nb = c.emit_gate_result(paths, "check_mining", errors, reviews)
    print("")
    print("==== 总门禁结果：%s ====" % ("通过（仍有 AI 复核项）" if nb == 0 else "未通过"))
    sys.exit(1 if nb else 0)


if __name__ == "__main__":
    main()
