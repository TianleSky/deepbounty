# -*- coding: utf-8 -*-
"""DeepBounty 证据门禁（evidence gate）：各终态的举证标准硬校验。

修 tyang-skill2 "20% tested_not_found 描述<50字符、filtered 举证无人看、报告门执行不一致"：
- tested_not_found：basis ≥ 50 字符、probe_count ≥ 3、tests 非空（修"太浅"）。
- filtered：filter_probe 有防护命中 + tests 含已试绕过；转 exhausted（矩阵 tested_not_found 不行——
  探到防护禁判 tnf，由 check_vuln_mining 硬拦）须 bypass_attempts ≥ 3 族。
- found：报告文件存在、含完整请求/响应段、无打码模式（*** / 【脱敏】 / 省略号占位）。
- 全部终态条目：cred_id 必须能在 cred/sessions.json 解析（或 none/unauthenticated）。

作为库被 check_mining.py 调用，也可单独跑：
    python evidence_gate.py --project <id> [--url-id URL00001 ...]
"""

import argparse
import glob
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c

REDACT_PATTERNS = [r"\*\*\*", r"【脱敏】", r"脱敏", r"打码", r"<redacted>", r"xxxxxx"]

# ---- 无害写证法（移植自 AutoHunter write_proof.py 五分类，见 vuln-recipes/authz.md）----
# 写/删/改类越权条目的证据形态判定：强四类（哨兵闭环/鉴权对照/幂等回写/旁路回读）缺一即复核。
_WRITE_OP_MARKERS = (
    "删除", "修改", "更新", "写操作", "新增", "重置密码", "保存",
    "delete", "remove", "update", "modify", "edit", "save", "insert", "create", "reset",
)
# 强证据形态（任一命中即视为有无害证法意识）
_HARMLESS_STRONG_PATTERNS = [
    r"哨兵", r"src_test_", r"自建测试",                     # sentinel 哨兵闭环
    r"未登录.{0,20}(401|403)", r"(401|403).{0,20}(200|成功)",  # authz_diff 鉴权对照
    r"对照", r"对比", r"匿名.{0,10}(拒绝|401|403)",
    r"幂等", r"写回原值", r"原值写回", r"值未变",             # idempotent 幂等回写
    r"旁路", r"before.{0,12}after", r"前后对比", r"修改后查询",  # side_read 旁路回读
    r"删除后查询", r"状态变化",
]
# 弱证据形态（成功文案+零影响）
_HARMLESS_WEAK_PATTERNS = [
    r'"data"\s*:\s*0\b', r'"affected(?:rows)?"\s*:\s*0\b', r'"count"\s*:\s*0\b',
    r"影响\s*0", r"0\s*行",
]

# SRC 报告门 §2 C 类「永不当洞」的标题/类型特征（机读硬拦，修"禁 C 类却批 131 个 low"）
C_CLASS_PATTERNS = [
    r"缺少.{0,8}(安全头|CSP|HSTS|X-Frame-Options|XFO|Content-Security-Policy)",
    r"Self-?XSS", r"登出\s*CSRF", r"只读\s*CSRF",
    r"(版本号?|堆栈|类名|内部\s*IP|路径)(信息)?(泄露|暴露|泄漏)",
    r"Go\s+binding", r"UUIDv1",
    r"客户端风控参数", r"a_bogus", r"msToken",
    r"分页无上限",
]


def check_basis_depth(uid, pname, e, errors):
    st = e.get("status")
    if st == "tested_not_found":
        basis = (e.get("basis") or "").strip()
        if len(basis) < c.MIN_BASIS_LEN_TNF:
            errors.append("[证据] %s %s 漏洞[%s] tested_not_found 的 basis 仅 %d 字符（<%d）——"
                          "必须写清测了什么、为什么判无（修'太浅'）"
                          % (uid, pname, e.get("vuln_type"), len(basis), c.MIN_BASIS_LEN_TNF))
        pc = e.get("probe_count")
        if isinstance(pc, int) and pc < c.MIN_PROBE_COUNT_TNF:
            errors.append("[证据] %s %s 漏洞[%s] probe_count=%d（<%d）——渐进探测未达最低探测数"
                          % (uid, pname, e.get("vuln_type"), pc, c.MIN_PROBE_COUNT_TNF))


def check_filtered_evidence(uid, pname, e, errors, reviews):
    """filtered 条目：必须有防护命中 + 已试绕过记录（bypass_attempts 不足只提示——
    绕过是 bypass 阶段职责；但 filter_probe 无防护命中的 filtered 是自相矛盾，硬错误）。"""
    if e.get("status") != "filtered":
        return
    fp = e.get("filter_probe")
    guards = set()
    if isinstance(fp, dict):
        guards = {v[0] for v in fp.values()
                  if isinstance(v, list) and v and v[0] in c.FILTER_PROBE_PROTECTION}
    if not guards:
        errors.append("[证据] %s %s 漏洞[%s] 记 filtered 但 filter_probe 无任何防护命中——"
                      "filtered 语义是'有信号+有防护'，无防护命中应记其他状态"
                      % (uid, pname, e.get("vuln_type")))
    attempts = e.get("bypass_attempts") or []
    if attempts and len(attempts) < c.MIN_BYPASS_FAMILIES:
        reviews.append("[复核] %s %s 漏洞[%s] bypass_attempts 仅 %d 族（<%d）——bypass 阶段须补足"
                       % (uid, pname, e.get("vuln_type"), len(attempts), c.MIN_BYPASS_FAMILIES))


def check_exhausted_bypass(uid, pname, e, errors):
    """矩阵 filtered 条目若已被 bypass 阶段判'仍绕不过'（bypass_attempts 存在）：
    必须 ≥ MIN_BYPASS_FAMILIES 族，否则不许终结。"""
    attempts = e.get("bypass_attempts") or []
    if e.get("status") == "filtered" and e.get("bypass_final") is True:
        if len(attempts) < c.MIN_BYPASS_FAMILIES:
            errors.append("[证据] %s %s 漏洞[%s] bypass_final=true 但仅 %d 族绕过尝试（<%d）——"
                          "不足 %d 族不得终结" % (uid, pname, e.get("vuln_type"), len(attempts),
                                                  c.MIN_BYPASS_FAMILIES, c.MIN_BYPASS_FAMILIES))


def check_authz_harmless_proof(uid, pname, e, reviews):
    """写/删/改类越权 found 条目的无害证法复核（复核级，不硬拦——移植 AutoHunter write_proof
    五分类：sentinel/authz_diff/idempotent/side_read 为强；成功文案+零影响为弱）。
    只盯 AUTHZ 前缀 + 写操作语义 + status=found 的条目。"""
    if e.get("status") != "found":
        return
    if c.vt_prefix(e.get("vuln_type")) != "AUTHZ":
        return
    blob = " ".join(str(e.get(k) or "") for k in ("vuln_type", "basis", "tests", "checkpoint_response"))
    low = blob.lower()
    if not any(m in low for m in _WRITE_OP_MARKERS):
        return
    if any(re.search(p, blob, re.I) for p in _HARMLESS_STRONG_PATTERNS):
        return
    weak = any(re.search(p, low) for p in _HARMLESS_WEAK_PATTERNS)
    reviews.append("[复核] %s %s 漏洞[%s] 写/删/改类越权缺无害证法形态%s——"
                   "应补：哨兵闭环（SRC_TEST_<rand> 自建自删+旁路回读）/ 鉴权对照（未登录 401↔登录 200）/ "
                   "幂等回写原值（affectedRows≥1 且值未变）/ 真实写删改的 before→after 闭环。无限制原则：真实数据可测，但必须有闭环证据，不能只贴成功文案"
                   % (uid, pname, e.get("vuln_type"),
                      "（且命中零影响弱形态）" if weak else ""))


def check_report_evidence(paths, errors, reviews):
    """found 报告零脱敏抽查：报告必须含完整请求/响应段，且无打码模式。"""
    rdir = paths["reports_dir"]
    if not os.path.isdir(rdir):
        return
    for fp in sorted(glob.glob(os.path.join(rdir, "VULN-VD-*.md"))):
        vid = os.path.splitext(os.path.basename(fp))[0]
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except Exception:
            continue
        if len(text) < 2000:
            errors.append("[报告] %s 正文 %d 字节过短（<2000）——证据不充分" % (vid, len(text)))
        for pat in REDACT_PATTERNS:
            if re.search(pat, text):
                errors.append("[报告] %s 命中打码模式 %r——证据零脱敏原则，禁止" % (vid, pat))
                break
        if "请求" not in text or "响应" not in text:
            errors.append("[报告] %s 缺完整请求/响应段" % vid)
        if "SRC提交稿" not in text or "完整请求包" not in text or "复现流程" not in text:
            errors.append("[报告] %s 缺 SRC提交稿（须含「SRC提交稿」「复现流程」「完整请求包」"
                          "三节，可直接粘贴提交）" % vid)
        # C 类「永不当洞」机读硬拦：标题（首行）命中 C 类特征 = 硬错误
        title = text.splitlines()[0] if text else ""
        for pat in C_CLASS_PATTERNS:
            if re.search(pat, title, re.IGNORECASE):
                errors.append("[报告] %s 标题命中 C 类（永不当洞）特征 %r——SRC 报告门 §2 C 禁止 found"
                              % (vid, pat))
                break


def check_cred_traceability(paths, errors):
    """矩阵终态条目的 cred_id 必须可解析（存在于 cred/sessions.json 或为 none/unauthenticated）。"""
    import cred_vault as vault
    sess = vault.load_sessions(paths).get("sessions", [])
    valid = {s.get("cred_id") for s in sess} | {"none", "unauthenticated", ""}
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
            if e.get("status") in ("tested_not_found", "doubtful", "filtered", "found"):
                cid = e.get("cred_id")
                if cid is not None and cid not in valid:
                    errors.append("[证据] %s %s 漏洞[%s] cred_id=%r 在 cred/sessions.json 中不存在"
                                  % (uid, pname, e.get("vuln_type"), cid))


def run_all(paths, url_ids=None, errors=None, reviews=None):
    """跑全部证据检查。供 check_mining.py 复用。返回 (errors, reviews)。"""
    errors = errors if errors is not None else []
    reviews = reviews if reviews is not None else []
    if url_ids:
        files = [os.path.join(paths["vuln_matrix_dir"], "%s.json" % u) for u in url_ids]
    else:
        files = sorted(glob.glob(os.path.join(paths["vuln_matrix_dir"], "*.json")))
    for fp in files:
        if not os.path.exists(fp):
            continue
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
            check_basis_depth(uid, pname, e, errors)
            check_filtered_evidence(uid, pname, e, errors, reviews)
            check_exhausted_bypass(uid, pname, e, errors)
            check_authz_harmless_proof(uid, pname, e, reviews)
    check_report_evidence(paths, errors, reviews)
    check_cred_traceability(paths, errors)
    return errors, reviews


def main():
    p = argparse.ArgumentParser(description="DeepBounty 证据门禁")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    p.add_argument("--url-id", nargs="*", default=None)
    args = p.parse_args()
    paths = c.project_paths(args.data_root, args.project)
    errors, reviews = run_all(paths, args.url_id)
    if errors:
        print("【证据硬错误（%d）】" % len(errors))
        for e in errors:
            print("  - " + e)
    else:
        print("【证据门禁通过】")
    if reviews:
        print("【待复核（%d）】" % len(reviews))
        for r in reviews:
            print("  - " + r)
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
