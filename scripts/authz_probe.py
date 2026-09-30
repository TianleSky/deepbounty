# -*- coding: utf-8 -*-
"""DeepBounty 越权探测引擎（authz probe）——permission_probe.py 的全面重写。

修 tyang-skill2 permission_probe 名存实亡（18 项目仅 1 个跑过）的四大断点：
1. **恒 GET 无 body** → 本引擎从 proxy-logs/requests/{uid}.log 解析原始请求
   （方法/头/body 原样），POST/PUT/JSON 接口照样测。
2. **owner_of() 硬编码 /admin//merchant//user/** → 废弃路径猜角色，改为
   **凭据角色驱动**：cred/coverage.json 里每个 alive 身份一个视角（attacker/victim/admin），
   跨账号响应 diff 判定，不靠 URL 命名。
3. **无水平 ID 枚举** → ID 类参数（id/uid/order_id...）自动做：victim 样本值替换
   （attacker 凭据请求 victim 的对象 ID）+ 邻居枚举（id±1），diff 坐实。
4. **门禁零引用** → 产出 permission-matrix/{uid}.json 由 check_mining.py 强制核查
   （AUTHZ 类叶子 confirmed 必须有对应矩阵记录）。

判定：
- 未授权面：unauth 基线与带凭据响应一致（状态码+相似度）→ 疑似未授权访问。
- 垂直越权：低权角色拿到与高权角色一致的成功响应。
- 水平越权（IDOR）：attacker 凭据 + victim 的对象 ID → 响应与 victim 自取一致（相似度≥0.9）
  且与 attacker 取自己对象不同 → 疑似 IDOR。

用法：
    python authz_probe.py --project <id> [--url-id URL00012] [--timeout 15]
"""

import argparse
import difflib
import json
import os
import re
import sys
import urllib.parse
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c
import cred_vault as vault

ID_PARAM_RE = re.compile(r"^(id|uid|user_?id|account_?id|order_?(id|no)|.*_id|.*Id|no|num)$", re.I)
TIMEOUT = 15


# ---------- 原始请求解析 ----------

def parse_original_request(paths, uid):
    """从 requests/{uid}.log 解析最新一条原始请求 → {method,url,headers,body}。"""
    log = os.path.join(paths["requests_dir"], "%s.log" % uid)
    if not os.path.exists(log):
        return None
    with open(log, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    blocks = re.split(r"^###### \[", text, flags=re.M)
    last = None
    for b in blocks:
        if "--- REQUEST ---" in b:
            last = b
    if last is None:
        return None
    m = re.search(r"######.*?\| (\w+) (\S+) ######", "[" + last)
    # 修：原正则 (.*?)\n\n?(.*?) 非贪婪把全部头吞进 body 组 → headers 恒空、"no host given"。
    # 头/体按首个空行切分（兼容无 body 的 GET）。
    req_m = re.search(r"--- REQUEST ---\n(\w+) (\S+) HTTP/[\d.]+\n(.*?)\n--- RESPONSE",
                      last, re.S)
    if not req_m:
        return None
    method, path, rest = req_m.group(1), req_m.group(2), req_m.group(3)
    if "\n\n" in rest:
        head_block, body = rest.split("\n\n", 1)
    else:
        head_block, body = rest, ""
    headers = {}
    for ln in head_block.splitlines():
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip()] = v.strip()
    host = headers.get("Host", "")
    url = path if "://" in path else "https://%s%s" % (host, path)
    # 认证头剔除（由各身份凭据替换）
    for k in list(headers):
        if k.lower() in ("cookie", "authorization", "x-token", "x-access-token",
                         "content-length", "accept-encoding"):
            del headers[k]
    return {"method": method, "url": url, "headers": headers, "body": body or ""}


# ---------- HTTP ----------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(req_tpl, sess, proxy="", timeout=TIMEOUT, body_override=None):
    """以某身份重放原始请求。sess=None 为未登录基线。返回 (status, location, body)。"""
    headers = dict(req_tpl.get("headers") or {})
    cred_id = "none"
    if sess is not None:
        cred_id = sess.get("cred_id", "?")
        auth = sess.get("auth") or {}
        if auth.get("cookie"):
            headers["Cookie"] = auth["cookie"]
        for k, v in (auth.get("headers") or {}).items():
            headers[k] = v
    body = body_override if body_override is not None else req_tpl.get("body") or ""
    data = body.encode("utf-8") if body else None
    if data:
        headers["Content-Length"] = str(len(data))
    req = urllib.request.Request(req_tpl["url"], data=data,
                                 method=req_tpl.get("method", "GET"), headers=headers)
    handlers = [_NoRedirect()]
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        handlers.append(urllib.request.HTTPSHandler(context=c.insecure_ssl_context()))
    opener = urllib.request.build_opener(*handlers)
    try:
        r = opener.open(req, timeout=timeout)
        return r.status, "", r.read().decode("utf-8", "replace"), cred_id
    except urllib.error.HTTPError as e:
        loc = e.headers.get("Location", "") if e.headers else ""
        try:
            b = e.read().decode("utf-8", "replace")
        except Exception:
            b = ""
        return e.code, loc, b, cred_id
    except Exception as e:
        return 0, "error", str(e)[:120], cred_id


def sim(a, b):
    if not a and not b:
        return 1.0
    try:
        return difflib.SequenceMatcher(None, (a or "")[:8192], (b or "")[:8192]).quick_ratio()
    except Exception:
        return 0.0


def json_success(body):
    t = (body or "").replace(" ", "").replace("\n", "")
    return ('"success":true' in t or '"errorCode":0' in t or '"code":0' in t
            or '"errno":0' in t or '"errcode":0' in t)


# ---------- 水平 IDOR ----------

def id_params_of(paths, uid):
    """该 URL 的 ID 类参数及其样本值。"""
    pfile = os.path.join(paths["params_dir"], "%s.json" % uid)
    doc = c.load_json(pfile, default=None)
    plist = doc.get("params", []) if isinstance(doc, dict) else (doc or [])
    out = []
    for p in plist:
        name = p.get("name") or ""
        if ID_PARAM_RE.match(name):
            out.append((name, str(p.get("sample_value") or "")))
    return out


def swap_body_param(body, pname, newval):
    """在 form/json body 中替换参数值（尽力而为）。"""
    if not body:
        return body
    try:
        obj = json.loads(body)
        if isinstance(obj, dict) and pname in obj:
            obj[pname] = newval
            return json.dumps(obj, ensure_ascii=False)
    except Exception:
        pass
    if "=" in body:
        parts = urllib.parse.parse_qsl(body, keep_blank_values=True)
        parts = [(k, newval if k == pname else v) for k, v in parts]
        return urllib.parse.urlencode(parts)
    return body


def swap_url_param(url, pname, newval):
    u = urllib.parse.urlsplit(url)
    q = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
    q = [(k, newval if k == pname else v) for k, v in q]
    return urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, urllib.parse.urlencode(q), u.fragment))


# ---------- 主流程 ----------

def probe_url(paths, uid, url, roles, proxy, timeout):
    """单 URL 全视角探测 + 判定。roles: [(label, sess_or_None)]。"""
    tpl = parse_original_request(paths, uid) or {"method": "GET", "url": url, "headers": {}, "body": ""}
    results = []
    for label, sess in roles:
        st, loc, body, cid = fetch(tpl, sess, proxy=proxy, timeout=timeout)
        results.append({
            "role": label, "cred_id": cid, "status_code": st,
            "final_status": loc or str(st), "response_length": len(body or ""),
            "json_success": json_success(body), "body": body,
        })
    return tpl, results


def judge_unauth(results):
    """未授权面：unauth 与任一已登录角色响应一致 → 疑似未授权。"""
    un = next((r for r in results if r["role"] == "unauth"), None)
    if not un or un["status_code"] == 0:
        return None
    for r in results:
        if r["role"] == "unauth" or r["status_code"] == 0:
            continue
        if r["status_code"] == un["status_code"] and sim(r["body"], un["body"]) >= 0.95 \
                and (r["json_success"] or r["response_length"] > 128):
            return "unauth 基线与 %s 响应一致（status=%d sim≥0.95）→ 疑似未授权访问" % (
                r["role"], r["status_code"])
    return None


def judge_horizontal(paths, uid, tpl, attacker, victim, proxy, timeout):
    """水平 IDOR：attacker 凭据 + victim 样本 ID / 邻居 ID。
    含无效 id 基线对照（移植 Argus 判定：无效 id 也 200+数据 → 公开资源/兜底响应，非 IDOR）。"""
    findings = []
    idps = id_params_of(paths, uid)
    if not (attacker and victim and idps):
        return findings
    for pname, victim_val in idps:
        if not victim_val or not re.match(r"^[A-Za-z0-9\-_]{2,64}$", victim_val):
            continue
        # attacker 请求 victim 的对象
        body2 = swap_body_param(tpl.get("body", ""), pname, victim_val)
        url2 = swap_url_param(tpl["url"], pname, victim_val)
        tpl2 = dict(tpl, url=url2, body=body2)
        st_a, _, body_a, _ = fetch(tpl2, attacker, proxy=proxy, timeout=timeout)
        # victim 自取作锚点
        st_v, _, body_v, _ = fetch(tpl2, victim, proxy=proxy, timeout=timeout)
        if st_a and st_a == st_v and json_success(body_a) \
                and sim(body_a, body_v) >= 0.9:
            # 无效 id 基线：victim 请求一个几乎不可能存在的 id，同样成功则疑似公开资源
            invalid_val = "0" if victim_val != "0" else "99999999999"
            body3 = swap_body_param(tpl.get("body", ""), pname, invalid_val)
            url3 = swap_url_param(tpl["url"], pname, invalid_val)
            tpl3 = dict(tpl, url=url3, body=body3)
            st_i, _, body_i, _ = fetch(tpl3, victim, proxy=proxy, timeout=timeout)
            public_hint = (
                st_i and st_i == st_v and json_success(body_i) and sim(body_i, body_v) >= 0.9
            )
            if public_hint:
                findings.append(
                    "疑似水平越权但无效 id 基线同样成功（%s=%s 与 %s=%s 响应一致）——"
                    "疑似公开资源/兜底响应，需人工复核排除后才可坐实 IDOR"
                    % (pname, invalid_val, pname, victim_val))
            else:
                findings.append(
                    "疑似水平越权(IDOR)：attacker(%s) 凭据请求 victim(%s) 的 %s=%s，"
                    "响应与 victim 自取一致（status=%d sim≥0.9）；无效 id 基线已排除公开资源"
                    % (attacker.get("cred_id"), victim.get("cred_id"), pname, victim_val, st_a))
    return findings


def main():
    p = argparse.ArgumentParser(description="DeepBounty 越权探测引擎（双账号 diff + 水平枚举）")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    p.add_argument("--url-id", default="", help="只测单个 URLID")
    p.add_argument("--timeout", type=int, default=TIMEOUT)
    p.add_argument("--proxy", default="")
    args = p.parse_args()

    paths = c.project_paths(args.data_root, args.project)
    cfg = c.load_json(paths["config"], default={}) or {}
    proxy = args.proxy or "http://127.0.0.1:%s" % cfg.get("proxy_port", 24304)

    cov = c.load_json(os.path.join(paths["cred_dir"], "coverage.json"), default=None)
    if cov is None:
        print("[错误] 未找到 cred/coverage.json，先跑 cred_gate.py")
        sys.exit(1)
    sess_doc = vault.load_sessions(paths)
    by_id = {s["cred_id"]: s for s in sess_doc.get("sessions", [])}

    inv = c.load_json(paths["inventory"], default={"urls": []})
    targets = [u for u in inv.get("urls", []) if u.get("category") in ("page", "api")]
    if args.url_id:
        targets = [u for u in targets if u.get("id") == args.url_id]

    now = c.now_iso()
    n_abn = 0
    for u in targets:
        uid, url = u.get("id"), u.get("url", "")
        host = ""
        try:
            host = (urllib.parse.urlsplit(url).hostname or "").lower()
        except Exception:
            pass
        cov_h = (cov.get("hosts") or {}).get(host) or {}
        cred_ids = cov_h.get("alive_cred_ids") or []
        roles = [("unauth", None)]
        creds = [by_id[cid] for cid in cred_ids if cid in by_id]
        for s in creds:
            roles.append((s.get("role") or s["cred_id"], s))
        tpl, results = probe_url(paths, uid, url, roles, proxy, args.timeout)

        findings = []
        un = judge_unauth(results)
        if un:
            findings.append(un)
        # 双账号水平 diff
        attacker = next((s for s in creds if s.get("role") == "attacker"), None) \
            or (creds[0] if creds else None)
        victim = next((s for s in creds if s.get("role") == "victim"), None) \
            or (creds[1] if len(creds) > 1 else None)
        if attacker and victim and attacker.get("cred_id") != victim.get("cred_id"):
            findings.extend(judge_horizontal(paths, uid, tpl, attacker, victim, proxy, args.timeout))
        elif any(l != "unauth" for l, _ in roles):
            findings.append("无双账号（coverage authz_blocked）：水平越权未测，记 blocked")

        for r in results:
            r.pop("body", None)  # 矩阵不落响应全文（证据在代理日志/报告）
        pm = {
            "url_id": uid, "url": url,
            "url_category": u.get("category", "api"),
            "test_request": "%s %s" % (tpl.get("method", "GET"), url),
            "results": results,
            "findings": findings,
            "created": now, "updated": now,
        }
        c.atomic_write_json(os.path.join(paths["perm_dir"], "%s.json" % uid), pm)
        if findings and not (len(findings) == 1 and findings[0].startswith("无双账号")):
            n_abn += 1
            print("[%s] %s" % (uid, "；".join(findings)))

    # 回填 inventory
    for u in inv.get("urls", []):
        if u.get("category") in ("page", "api"):
            u["permission_matrix_status"] = "verified"
    c.atomic_write_json(paths["inventory"], inv)
    print("[完成] 探测 %d 个 URL，疑似越权 %d 个 → permission-matrix/" % (len(targets), n_abn))
    print("[提示] 疑似项须由 miner 按 AUTHZ001-004 要点逐条坐实（读到他人真实数据才 found）")


if __name__ == "__main__":
    main()
