# -*- coding: utf-8 -*-
"""DeepBounty WAF 软阻断判定器（waf baseline）——移植 Agentic-Bug-Hunter
waf_response_analyzer.py 的三档 verdict 模型（见 references/waf-bypass.md「软阻断判定」）。

解决的核心问题：WAF 厂商故意对拦截返回 200+挑战页，裸看状态码会把 blocked 误判为 bypassed。
本工具先采样「阻断基线」（已知恶意 payload 被拦时的响应特征），再对每个探测响应三档分类：

- blocked       ：body 命中厂商签名，或长度≈阻断基线（±5%）
- bypassed      ：状态 ∈ {200,201,204,301,302,401,500,502,503} 且 body ≠ 基线 且无厂商签名
                  （401/500 也算穿过边缘到达后端，是绕过胜利，不是失败）
- needs_review  ：状态正常但 body 含糊（人工复核）

用法：
    # 1) 采样阻断基线（对目标发一个已知恶意 payload，记录被拦响应特征）
    python waf_baseline.py calibrate --url "https://t/search?q=x" --param q --out baseline.json
    # 2) 分类一个已抓响应
    python waf_baseline.py classify --baseline baseline.json --status 200 --length 2048 \
        --body-file resp.html [--headers-file resp.hdr]
    # 3) 一步探测：发请求并分类
    python waf_baseline.py probe --baseline baseline.json --url "https://t/search?q=<payload>"

bypass 子代理纪律：每次绕过尝试的响应都应过 classify，verdict 记入矩阵 bypass_attempts.result。
"""

import argparse
import json
import os
import re
import sys
import urllib.parse
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c

BYPASS_STATUSES = {200, 201, 204, 301, 302, 401, 500, 502, 503}
LENGTH_TOLERANCE = 0.05  # 与阻断基线长度差 ±5% 内视为 blocked

# 厂商签名（body/headers 小写子串匹配）——覆盖 waf-bypass.md 族 B1 分诊表 + 国内厂商
VENDOR_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cloudflare", "attention required", "error 1020", "error 1010",
                   "challenge-platform", "__cf_chl"],
    "Akamai": ["akamaighost", "akamai", "reference #"],
    "Sucuri": ["x-sucuri", "sucuri", "cloudproxy"],
    "Imperva": ["incap_ses", "x-iinfo", "incapsula", "_incapsula_", "visid_incap"],
    "F5": ["request rejected", "support id", "ts01", "f5 xc", "big-ip"],
    "AWS": ["x-amzn", "awselb", "x-amz-cf", "aws waf"],
    "ModSecurity": ["mod_security", "modsecurity", "406 not acceptable"],
    "Vercel": ["x-vercel", "vercel"],
    "SafeDog": ["safedog", "安全狗"],
    "D-Shield": ["d盾", "d盾防火墙"],
    "Yunjiasu": ["yunsuo", "云锁"],
    "Anquanbao": ["anquanbao", "安全宝"],
}

# 拦截页 Log/Support/Incident ID 提取（报告附上可让厂商定位触发规则）
LOG_ID_PATTERNS = [
    r"Support ID[:\s]*([0-9A-Za-z\-]+)",
    r"Incident ID[:\s]*([0-9A-Za-z\-]+)",
    r"Reference #([0-9a-fA-F.]+)",
    r"Ray ID[:\s]*([0-9a-fA-F]+)",
    r"X-Sucuri-ID[:\s]*([0-9A-Za-z/]+)",
]

DEFAULT_PROBE = '<script>alert(1)</script>'


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_get(url, proxy="", timeout=15):
    """GET 并返回 (status, headers_text, body)。异常返回 (0, "", error)。"""
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (DeepBounty waf-baseline)"})
    handlers = [_NoRedirect()]
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        handlers.append(urllib.request.HTTPSHandler(context=c.insecure_ssl_context()))
    opener = urllib.request.build_opener(*handlers)
    try:
        r = opener.open(req, timeout=timeout)
        hdrs = "\n".join("%s: %s" % (k, v) for k, v in r.headers.items())
        return r.status, hdrs, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        hdrs = "\n".join("%s: %s" % (k, v) for k, v in (e.headers.items() if e.headers else []))
        try:
            b = e.read().decode("utf-8", "replace")
        except Exception:
            b = ""
        return e.code, hdrs, b
    except Exception as e:
        return 0, "", str(e)[:200]


def detect_vendors(text):
    low = (text or "").lower()
    return [name for name, sigs in VENDOR_SIGNATURES.items()
            if any(s.lower() in low for s in sigs)]


def extract_log_ids(text):
    ids = []
    for pat in LOG_ID_PATTERNS:
        m = re.search(pat, text or "")
        if m:
            ids.append(m.group(0))
    return ids


def cmd_calibrate(args):
    """采样阻断基线：对目标发已知恶意 payload，记录被拦响应特征。"""
    payload = args.payload or DEFAULT_PROBE
    if args.param:
        sep = "&" if urllib.parse.urlsplit(args.url).query else "?"
        url = "%s%s%s=%s" % (args.url, sep, args.param, urllib.parse.quote(payload))
    else:
        url = args.url
    st, hdrs, body = http_get(url, proxy=args.proxy, timeout=args.timeout)
    if st == 0:
        print("[错误] 基线请求失败：%s" % body)
        sys.exit(1)
    vendors = detect_vendors(hdrs + "\n" + body)
    baseline = {
        "url": args.url, "probe_payload": payload,
        "block_status": st, "block_length": len(body or ""),
        "vendors": vendors, "log_ids": extract_log_ids(hdrs + "\n" + body),
        "created": c.now_iso(),
    }
    c.atomic_write_json(args.out, baseline)
    print("[基线] status=%d length=%d 厂商=%s → %s"
          % (st, len(body or ""), ",".join(vendors) or "未识别", args.out))
    if not vendors:
        print("[提示] 未识别厂商签名——该 payload 可能未被拦（或厂商未知），"
              "建议换更明显的 payload 重采样，否则 classify 只能靠长度近似")


def classify(status, length, body, headers, baseline):
    """三档分类。返回 (verdict, reasons[])。"""
    reasons = []
    text = (headers or "") + "\n" + (body or "")
    vendors = detect_vendors(text)
    log_ids = extract_log_ids(text)

    # 厂商签名命中 → blocked（签名出现在响应里几乎必是拦截/挑战页）
    if vendors:
        reasons.append("命中厂商签名: %s" % ",".join(vendors))
        if log_ids:
            reasons.append("Log ID: %s" % "; ".join(log_ids))
        return "blocked", reasons

    # 长度≈阻断基线 → blocked
    bl = (baseline or {}).get("block_length")
    if isinstance(bl, int) and bl > 0 and length is not None:
        if abs(length - bl) <= max(64, bl * LENGTH_TOLERANCE):
            reasons.append("长度 %d ≈ 阻断基线 %d（±%.0f%%）" % (length, bl, LENGTH_TOLERANCE * 100))
            return "blocked", reasons

    # 状态白名单 + 无签名 + 长度偏离基线 → bypassed
    if status in BYPASS_STATUSES:
        reasons.append("状态 %d 在穿过集合且未命中签名/基线" % status)
        if status in (401, 500):
            reasons.append("注意：%d 表示请求已穿过边缘到达后端（绕过胜利，非失败）" % status)
        return "bypassed", reasons

    reasons.append("状态 %d 含糊，需人工复核" % status)
    return "needs_review", reasons


def cmd_classify(args):
    baseline = c.load_json(args.baseline, default=None) if args.baseline else None
    body = ""
    if args.body_file and os.path.exists(args.body_file):
        with open(args.body_file, "r", encoding="utf-8", errors="replace") as f:
            body = f.read()
    headers = ""
    if args.headers_file and os.path.exists(args.headers_file):
        with open(args.headers_file, "r", encoding="utf-8", errors="replace") as f:
            headers = f.read()
    length = args.length if args.length is not None else len(body)
    verdict, reasons = classify(args.status, length, body, headers, baseline)
    out = {"verdict": verdict, "reasons": reasons, "status": args.status, "length": length}
    print(json.dumps(out, ensure_ascii=False, indent=2))
    sys.exit(0 if verdict == "bypassed" else (2 if verdict == "blocked" else 3))


def cmd_probe(args):
    baseline = c.load_json(args.baseline, default=None) if args.baseline else None
    st, hdrs, body = http_get(args.url, proxy=args.proxy, timeout=args.timeout)
    if st == 0:
        print(json.dumps({"verdict": "needs_review", "reasons": ["请求失败: %s" % body]},
                         ensure_ascii=False))
        sys.exit(3)
    verdict, reasons = classify(st, len(body or ""), body, hdrs, baseline)
    out = {"verdict": verdict, "reasons": reasons, "status": st, "length": len(body or "")}
    print(json.dumps(out, ensure_ascii=False, indent=2))
    sys.exit(0 if verdict == "bypassed" else (2 if verdict == "blocked" else 3))


def main():
    p = argparse.ArgumentParser(description="DeepBounty WAF 软阻断三档判定器")
    sub = p.add_subparsers(dest="cmd", required=True)

    pc = sub.add_parser("calibrate", help="采样阻断基线")
    pc.add_argument("--url", required=True)
    pc.add_argument("--param", default="", help="把探针 payload 注入该 query 参数")
    pc.add_argument("--payload", default="", help="已知恶意 payload（默认 XSS 探针）")
    pc.add_argument("--out", default="waf-baseline.json")
    pc.add_argument("--proxy", default="")
    pc.add_argument("--timeout", type=int, default=15)
    pc.set_defaults(fn=cmd_calibrate)

    pj = sub.add_parser("classify", help="分类已抓响应")
    pj.add_argument("--baseline", default="")
    pj.add_argument("--status", type=int, required=True)
    pj.add_argument("--length", type=int, default=None)
    pj.add_argument("--body-file", default="")
    pj.add_argument("--headers-file", default="")
    pj.set_defaults(fn=cmd_classify)

    pp = sub.add_parser("probe", help="发请求并分类")
    pp.add_argument("--baseline", default="")
    pp.add_argument("--url", required=True)
    pp.add_argument("--proxy", default="")
    pp.add_argument("--timeout", type=int, default=15)
    pp.set_defaults(fn=cmd_probe)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
