# -*- coding: utf-8 -*-
"""DeepBounty 端点能力画像 + VulnType×Endpoint 兼容性矩阵（借 Argus EndpointCapability）。

对每个入库 URL 计算能力画像（方法/参数位置/Content-Type/参数名与样本值信号/是否文件上传/
是否 XML 体/是否需鉴权/是否网关），再按兼容规则生成「该 URL 每个参数适用的漏洞类白名单」，
杜绝无意义组合（如对无参 GET 测 SQLi、对 JSON 接口测 XXE）。

产出：endpoint-capabilities.json
用法：
    python capability_matrix.py --project <id> [--data-root pentest-data]
"""

import argparse
import json
import os
import re
import sys
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c

# ---- 参数名/值信号词表 ----
SSRF_NAME_HINTS = {"url", "link", "uri", "callback", "webhook", "target", "host", "domain",
                   "site", "src", "source", "dest", "redirect", "fetch", "proxy", "img",
                   "image", "pic", "avatar", "feed", "api", "endpoint", "addr", "address",
                   "webpage", "page_url", "file_url", "download_url", "import", "load"}
PATH_NAME_HINTS = {"file", "filepath", "path", "filename", "fname", "dir", "directory",
                   "folder", "template", "tpl", "page", "include", "doc", "document",
                   "download", "attach", "attachment", "resource", "name", "conf", "config"}
UPLOAD_NAME_HINTS = {"file", "upload", "attach", "attachment", "avatar", "img", "image",
                     "pic", "photo", "media", "import"}
ID_NAME_HINTS = {"id", "uid", "user_id", "userid", "account", "account_id", "order_id",
                 "orderid", "order_no", "orderno", "no", "num", "number", "code",
                 "product_id", "goods_id", "item_id", "msg_id", "message_id", "comment_id",
                 "address_id", "card_id", "patient_id", "case_id", "record_id", "file_id"}
ENUM_PATH_HINTS = ("login", "register", "reg", "signin", "signup", "reset", "forget",
                   "forgot", "findpwd", "check", "exists", "validate", "send")
SMS_PATH_HINTS = ("sms", "captcha", "verify", "code", "otp")
BIZ_PATH_HINTS = ("order", "pay", "coupon", "prize", "draw", "lottery", "sign", "seckill",
                  "buy", "purchase", "exchange", "redeem", "points", "credit", "balance",
                  "transfer", "withdraw", "refund")
URL_VALUE_RE = re.compile(r"^(https?://|//|[a-z0-9\-]+\.(com|cn|net|org|io|gov|edu))", re.I)
XML_CT_RE = re.compile(r"xml|soap", re.I)
JSON_CT_RE = re.compile(r"json", re.I)
MULTIPART_RE = re.compile(r"multipart/form-data", re.I)

# ---- 兼容规则：漏洞类 → 判定函数（输入 cap 画像与参数信息，返回是否适用）----
# cap: {methods, params: [{name, source, type, sample_value}], content_types, has_upload,
#       has_xml, is_gateway, auth_seen, path_lower}


def _has_params(cap):
    return bool(cap["params"])


def _param_matches(cap, names):
    for p in cap["params"]:
        n = (p.get("name") or "").lower().split(".")[-1]
        if n in names:
            return True
    return False


def _param_value_url(cap):
    for p in cap["params"]:
        v = str(p.get("sample_value") or "")
        if URL_VALUE_RE.match(v):
            return True
    return False


def _reflected_type(cap):
    # 响应为 html/js/json 均可能回显；保守：有参数即可测反射面
    return _has_params(cap)


def _path_has(cap, hints):
    return any(h in cap["path_lower"] for h in hints)


COMPAT_RULES = {
    "SQL注入": lambda cap: _has_params(cap),
    "NoSQL注入": lambda cap: _has_params(cap) and (cap["has_json"] or _param_matches(cap, {"filter", "query", "where", "search", "sort", "order"})),
    "XSS": _reflected_type,
    "命令注入": lambda cap: _has_params(cap) and _param_matches(
        cap, {"cmd", "command", "exec", "ping", "host", "ip", "domain", "dir", "path",
              "file", "name", "filename", "arg", "param", "query", "addr", "target"} | SSRF_NAME_HINTS) or _has_params(cap),
    "SSRF": lambda cap: _param_matches(cap, SSRF_NAME_HINTS) or _param_value_url(cap),
    "XXE": lambda cap: cap["has_xml"],
    "路径穿越": lambda cap: _param_matches(cap, PATH_NAME_HINTS),
    "文件上传": lambda cap: cap["has_upload"] or _param_matches(cap, UPLOAD_NAME_HINTS),
    "SSTI": _reflected_type,
    "ELI": _reflected_type,
    "用户枚举": lambda cap: _path_has(cap, ENUM_PATH_HINTS),
    "越权": lambda cap: cap["auth_seen"] or _param_matches(cap, ID_NAME_HINTS),
    "IDOR": lambda cap: _param_matches(cap, ID_NAME_HINTS),
    "JWT": lambda cap: cap["has_jwt"],
    "优惠/积分/抽奖重复使用": lambda cap: _path_has(cap, BIZ_PATH_HINTS),
    "竞态": lambda cap: _path_has(cap, BIZ_PATH_HINTS) or _param_matches(
        cap, {"count", "num", "amount", "quantity", "stock", "balance", "price"}),
    "重放": lambda cap: _path_has(cap, BIZ_PATH_HINTS + SMS_PATH_HINTS),
    "验证码/短信绕过": lambda cap: _path_has(cap, SMS_PATH_HINTS),
    "开放重定向": lambda cap: _param_matches(cap, {"redirect", "redirect_uri", "redirect_url",
                                                   "return", "return_url", "returnurl", "next",
                                                   "goto", "jump", "to", "target", "url", "link"}),
    "CORS": lambda cap: True,  # 任何接口都可测 CORS 头
    "敏感信息泄露": lambda cap: True,  # 响应审查通用
}

# generic / business_logic 归类（与 checkpoints 前缀映射解耦，矩阵 category 用）
CATEGORY_OF = {
    "SQL注入": "generic", "NoSQL注入": "generic", "XSS": "generic", "命令注入": "generic",
    "SSRF": "generic", "XXE": "generic", "路径穿越": "generic", "文件上传": "generic",
    "SSTI": "generic", "ELI": "generic", "JWT": "generic", "开放重定向": "generic",
    "CORS": "generic", "敏感信息泄露": "generic",
    "用户枚举": "business_logic", "越权": "business_logic", "IDOR": "business_logic",
    "优惠/积分/抽奖重复使用": "business_logic", "竞态": "business_logic",
    "重放": "business_logic", "验证码/短信绕过": "business_logic",
}


def build_cap(paths, url_rec):
    """由 url-inventory 记录 + params 文件 + failed_index 构建端点能力画像。"""
    uid = url_rec.get("id")
    url = url_rec.get("url", "")
    u = urlsplit(url)
    params = []
    pfile = os.path.join(paths["params_dir"], "%s.json" % uid)
    pdoc = c.load_json(pfile, default=None)
    if isinstance(pdoc, dict):
        params = pdoc.get("params", []) or []
    elif isinstance(pdoc, list):
        params = pdoc
    if not params:
        params = [{"name": n, "source": "", "type": "", "sample_value": ""}
                  for n in (url_rec.get("param_names") or [])]

    # content-type / upload / xml / jwt 线索：只扫 REQUEST 段（响应预览里的 xml 字样不算）
    content_types, has_upload, has_xml, has_json, has_jwt = set(), False, False, False, False
    rlog = os.path.join(paths["requests_dir"], "%s.log" % uid)
    if os.path.exists(rlog):
        try:
            with open(rlog, "r", encoding="utf-8", errors="replace") as f:
                head = f.read(65536)
            # 只取 --- REQUEST --- 到 --- RESPONSE 之间的请求原文（可能多块，全取）
            req_parts = re.findall(r"--- REQUEST ---\n(.*?)\n--- RESPONSE", head, re.S)
            req_text = "\n".join(req_parts) if req_parts else head
            for m in re.finditer(r"(?i)^content-type:\s*(.+)$", req_text, re.M):
                content_types.add(m.group(1).strip().lower())
            has_upload = any(MULTIPART_RE.search(ct) for ct in content_types)
            has_xml = any(XML_CT_RE.search(ct) for ct in content_types) \
                or bool(re.search(r"\n\s*<\?xml", req_text))
            has_json = any(JSON_CT_RE.search(ct) for ct in content_types)
            has_jwt = bool(re.search(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", req_text))
        except Exception:
            pass

    # 鉴权线索：failed_index 里同 URL 有 401/403，或成功报文带认证头
    auth_seen = has_jwt
    for rec in c.load_jsonl(paths["failed_index"]):
        if rec.get("id") == uid or rec.get("url") == url:
            codes = rec.get("status_codes") or {}
            if any(str(k).startswith(("401", "403")) for k in codes):
                auth_seen = True
    if not auth_seen and os.path.exists(rlog):
        try:
            with open(rlog, "r", encoding="utf-8", errors="replace") as f:
                head = f.read(32768)
            if re.search(r"(?i)^(authorization|cookie|x-token|x-access-token):", head, re.M):
                auth_seen = True
        except Exception:
            pass

    return {
        "url_id": uid,
        "url": url,
        "host": (u.hostname or "").lower(),
        "path_lower": (u.path or "/").lower(),
        "methods": url_rec.get("methods") or ["GET"],
        "category": url_rec.get("category", "api"),
        "params": params,
        "content_types": sorted(content_types),
        "has_upload": has_upload,
        "has_xml": has_xml,
        "has_json": has_json,
        "has_jwt": has_jwt,
        "auth_seen": auth_seen,
    }


def applicable_vulns(cap):
    """按兼容规则计算该端点适用的漏洞类 → {vuln_type: category}。"""
    out = {}
    for vt, rule in COMPAT_RULES.items():
        try:
            if rule(cap):
                out[vt] = CATEGORY_OF.get(vt, "generic")
        except Exception:
            continue
    return out


def main():
    p = argparse.ArgumentParser(description="端点能力画像 + 漏洞类兼容矩阵")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    args = p.parse_args()

    paths = c.project_paths(args.data_root, args.project)
    inv = c.load_json(paths["inventory"], default={"urls": []})
    endpoints = []
    for u in inv.get("urls", []):
        if u.get("category") not in ("page", "api"):
            continue
        cap = build_cap(paths, u)
        cap["applicable"] = applicable_vulns(cap)
        endpoints.append(cap)

    doc = {
        "_note": "端点能力画像与漏洞类兼容矩阵（capability_matrix.py 生成；task_tree.py 据此建树）",
        "count": len(endpoints),
        "endpoints": endpoints,
        "generated": c.now_iso(),
    }
    c.atomic_write_json(paths["endpoint_caps"], doc)
    n_params = sum(len(e["params"]) for e in endpoints)
    print("[完成] 端点画像 %d 个（参数共 %d 个）→ %s" % (len(endpoints), n_params, paths["endpoint_caps"]))
    vt_stat = {}
    for e in endpoints:
        for vt in e["applicable"]:
            vt_stat[vt] = vt_stat.get(vt, 0) + 1
    for vt, n in sorted(vt_stat.items(), key=lambda kv: -kv[1]):
        print("       %-16s 适用端点 %d 个" % (vt, n))


if __name__ == "__main__":
    main()
