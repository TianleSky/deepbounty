# -*- coding: utf-8 -*-
"""DeepBounty 凭据验活（cred verify）：区分度探针 + JWT exp 强制 + 登录包重放续期。

修复 tyang-skill2 假存活断点：
- 提取即 login_status=success、344 个身份从未验活 → 本脚本：cred 导入后 status=unknown，
  **未验活（unknown）不得消费**；验活通过才 alive。
- "无 GET 探针跳过不改状态"、"不误杀判活" → 本脚本：**区分度探针**——同一探针分别带/不带凭据
  各发一次，响应无区分度（状态码+长度+相似度一致）→ 不判活（保持 unknown，不算 alive）。
- 138 个过期 JWT 却 success → JWT exp 强制解析：过期直接 expired，无需发包。

续期：失效（expired）且有 login_packet / token_endpoint 时自动重放刷新，刷新后重验。

用法：
    python cred_verify.py --project <id> [--write] [--cred CRED0001] [--probe-url https://...]
    python cred_verify.py --project <id> --write --proxy http://127.0.0.1:24304
"""

import argparse
import base64
import difflib
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c
import cred_vault as vault

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) DeepBounty-CredVerify/1.0"
TIMEOUT = 15


# ---------- JWT exp ----------

def _jwt_exp(token):
    """解析 JWT exp（秒级 epoch）；非 JWT 返回 None。"""
    parts = (token or "").split(".")
    if len(parts) != 3:
        return None
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        obj = json.loads(base64.urlsafe_b64decode(payload.encode("utf-8")))
        exp = obj.get("exp")
        return int(exp) if exp else None
    except Exception:
        return None


def _find_jwt_exp(auth):
    """在 cookie/headers 里找 JWT，返回最早 exp（秒）或 None。"""
    texts = []
    if auth.get("cookie"):
        texts.append(auth["cookie"])
    texts.extend(str(v) for v in (auth.get("headers") or {}).values())
    exps = []
    for t in texts:
        for m in re.finditer(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", t):
            e = _jwt_exp(m.group(0))
            if e:
                exps.append(e)
    return min(exps) if exps else None


# ---------- HTTP ----------

def _http(url, method="GET", headers=None, body=None, proxy=""):
    """发请求，返回 (status, resp_headers, body_bytes)。网络错误返回 (0, {}, b'')。"""
    hdrs = {"User-Agent": UA}
    hdrs.update(headers or {})
    data = body.encode("utf-8") if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        ctx = c.insecure_ssl_context()
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=TIMEOUT) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        try:
            return e.code, dict(e.headers or {}), e.read()
        except Exception:
            return e.code, {}, b""
    except Exception:
        return 0, {}, b""


def _auth_headers(sess):
    """会话凭据 → 请求头（cookie + 自定义认证头全带）。"""
    auth = sess.get("auth") or {}
    hdrs = dict(auth.get("headers") or {})
    cookie = auth.get("cookie") or auth.get("cookie_value") or ""
    if cookie:
        hdrs["Cookie"] = cookie
    return hdrs


def _similarity(a, b):
    """两响应体相似度（difflib 比率，截断防大 body）。"""
    a = (a or b"")[:8192]
    b = (b or b"")[:8192]
    if not a and not b:
        return 1.0
    try:
        return difflib.SequenceMatcher(None, a, b).quick_ratio()
    except Exception:
        return 0.0


def _looks_like_login(status, headers, body, url):
    """响应是否像"被踢到登录/未授权"。"""
    if status in (401, 403):
        return True
    loc = ""
    for k, v in (headers or {}).items():
        if k.lower() == "location":
            loc = v
    if status in (301, 302, 303, 307, 308) and re.search(r"login|signin|auth|sso", loc, re.I):
        return True
    head = (body or b"")[:2048].decode("utf-8", "replace").lower()
    if re.search(r"登录|登陆|sign in|log in|未登录|请先登录|unauthorized|token.*(invalid|expired|失效|过期)", head):
        return True
    if url and re.search(r"login|signin", url, re.I) and status == 200:
        return True
    return False


# ---------- 探针选择 ----------

def pick_probe(paths, sess, override=""):
    """为会话挑选验活探针：优先 session.probe_url；否则从该 host 的 url-inventory 里
    挑一个 GET 且 category=api/page 的接口（排除登录/登出路径）。"""
    if override:
        return override
    if sess.get("probe_url"):
        return sess["probe_url"]
    hosts = set(sess.get("hosts") or [])
    inv = c.load_json(paths["inventory"], default={}) or {}
    for u in inv.get("urls", []):
        url = u.get("url", "")
        try:
            from urllib.parse import urlsplit
            h = (urlsplit(url).hostname or "").lower()
        except Exception:
            continue
        if hosts and h not in hosts:
            continue
        if "GET" not in (u.get("methods") or ["GET"]):
            continue
        if re.search(r"login|logout|signin|signout|captcha|send.?sms|register", url, re.I):
            continue
        if u.get("category") in ("api", "page"):
            return url
    return ""


# ---------- 验活核心 ----------

def verify_one(paths, sess, proxy="", probe_override=""):
    """区分度验活单个会话。返回 (new_status, reason)。

    流程：JWT exp 过期 → expired（不发包）。
    探针带凭据 vs 不带凭据各一次：
      - 两者一致（状态码相同且相似度≥0.98）→ 探针无区分度 → 保持 unknown（不判活，不误杀）
      - 带凭据像登录页/401/403 → expired
      - 带凭据 2xx 且与不带凭据有区分 → alive
      - 网络错误 → 保持 unknown（reason 注明）
    """
    now = time.time()
    exp = _find_jwt_exp(sess.get("auth") or {})
    if exp:
        sess["token_exp"] = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(exp))
        if exp < now:
            return "expired", "JWT exp 已过期（%s）" % sess["token_exp"]

    probe = pick_probe(paths, sess, probe_override)
    if not probe:
        return sess.get("status", "unknown"), "无可用探针（该 host 无 GET 接口），保持现状待人工 --probe-url"

    hdrs = _auth_headers(sess)
    s1, h1, b1 = _http(probe, headers=hdrs, proxy=proxy)          # 带凭据
    s0, h0, b0 = _http(probe, headers={}, proxy=proxy)            # 不带凭据
    if s1 == 0:
        return sess.get("status", "unknown"), "探针网络错误（%s），保持现状" % probe

    sim = _similarity(b1, b0)
    if s1 == s0 and sim >= 0.98:
        return "unknown", "探针无区分度（带/不带凭据响应一致 status=%d sim=%.2f），不判活" % (s1, sim)
    if _looks_like_login(s1, h1, b1, probe):
        return "expired", "带凭据响应呈未登录特征（status=%d probe=%s）" % (s1, probe)
    if 200 <= s1 < 400:
        return "alive", "区分度验活通过（带凭据 %d/%dB vs 不带 %d/%dB sim=%.2f）" % (
            s1, len(b1), s0, len(b0), sim)
    return sess.get("status", "unknown"), "带凭据响应异常 status=%d，保持现状" % s1


def try_renew(paths, sess, accounts, proxy=""):
    """失效自救：优先重放 login_packet，其次 token_endpoint。成功刷新凭据返回 True。"""
    acc = next((a for a in accounts if a.get("account_id") == sess.get("account_id")), None)
    pkt = (acc or {}).get("login_packet") or {}
    if pkt.get("url") and pkt.get("method"):
        s, h, b = _http(pkt["url"], method=pkt["method"], headers=pkt.get("headers") or {},
                        body=pkt.get("body") or None, proxy=proxy)
        if s and s < 400:
            new_cookie = "; ".join(v for k, v in (h or {}).items() if k.lower() == "set-cookie")
            if new_cookie:
                pairs = {}
                for part in (sess.get("auth", {}).get("cookie") or "").split(";"):
                    if "=" in part:
                        pairs[part.split("=", 1)[0].strip()] = part.strip()
                for nc in new_cookie.split("; "):
                    if "=" in nc:
                        pairs[nc.split("=", 1)[0].strip()] = nc.split(";")[0].strip()
                sess.setdefault("auth", {})["cookie"] = "; ".join(pairs.values())
                return True
            try:
                obj = json.loads(b.decode("utf-8", "replace"))
                for key in ("token", "access_token", "data"):
                    tok = obj.get(key) if isinstance(obj, dict) else None
                    if isinstance(tok, dict):
                        tok = tok.get("token") or tok.get("access_token")
                    if tok and isinstance(tok, str):
                        sess.setdefault("auth", {}).setdefault("headers", {})["Authorization"] = \
                            "Bearer " + tok if not tok.lower().startswith("bearer ") else tok
                        return True
            except Exception:
                pass
    te = sess.get("token_endpoint") or {}
    if te.get("url"):
        s, h, b = _http(te["url"], method=te.get("method", "POST"),
                        headers=te.get("headers") or {}, body=te.get("body") or None, proxy=proxy)
        if s and s < 400:
            if te.get("renew") == "cookie":
                new_cookie = "; ".join(v for k, v in (h or {}).items() if k.lower() == "set-cookie")
                if new_cookie:
                    sess.setdefault("auth", {})["cookie"] = new_cookie
                    return True
            elif te.get("renew") == "body" and te.get("field"):
                try:
                    obj = json.loads(b.decode("utf-8", "replace"))
                    val = obj
                    for seg in te["field"].split("."):
                        val = val.get(seg) if isinstance(val, dict) else None
                    if val:
                        target = te.get("target", "")
                        if target.startswith("cookie:"):
                            sess.setdefault("auth", {})["cookie"] = "%s=%s" % (target[7:], val)
                        elif target:
                            sess.setdefault("auth", {}).setdefault("headers", {})[target] = str(val)
                        return True
                except Exception:
                    pass
    return False


def main():
    p = argparse.ArgumentParser(description="DeepBounty 凭据区分度验活 + JWT exp + 续期")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    p.add_argument("--write", action="store_true", help="回写 cred/sessions.json（默认只演练打印）")
    p.add_argument("--cred", default="", help="只验指定 cred_id")
    p.add_argument("--probe-url", default="", help="人工指定验活探针 URL")
    p.add_argument("--proxy", default="", help="留痕代理（默认读 config.proxy_port）")
    p.add_argument("--no-renew", action="store_true", help="关闭失效自动续期")
    args = p.parse_args()

    paths = c.project_paths(args.data_root, args.project)
    cfg = c.load_json(paths["config"], default={}) or {}
    proxy = args.proxy or ("http://127.0.0.1:%s" % cfg.get("proxy_port", 24304))
    doc = vault.load_sessions(paths)
    accs = vault.load_accounts(paths).get("accounts", [])

    targets = [s for s in doc.get("sessions", []) if not args.cred or s.get("cred_id") == args.cred]
    if not targets:
        print("[提示] 无会话可验")
        return
    stat = {"alive": 0, "expired": 0, "unknown": 0, "revoked": 0, "renewed": 0}
    for sess in targets:
        if sess.get("status") == "revoked":
            stat["revoked"] += 1
            continue
        if sess.get("is_anonymous"):
            sess["status"] = "alive"  # 匿名基线恒可用（无凭据可过期）
            sess["verify"] = {"at": c.now_iso(), "method": "anonymous-baseline",
                              "verdict_reason": "匿名基线无需验活"}
            stat["alive"] += 1
            continue
        new_status, reason = verify_one(paths, sess, proxy=proxy, probe_override=args.probe_url)
        if new_status == "expired" and not args.no_renew:
            if try_renew(paths, sess, accs, proxy=proxy):
                stat["renewed"] += 1
                new_status, reason = verify_one(paths, sess, proxy=proxy,
                                                probe_override=args.probe_url)
                reason = "续期重放后重验：" + reason
        sess["status"] = new_status
        sess["verify"] = {"at": c.now_iso(), "method": "differential+jwt_exp",
                          "probe_url": pick_probe(paths, sess, args.probe_url),
                          "verdict_reason": reason}
        sess["updated"] = c.now_iso()
        stat[new_status] = stat.get(new_status, 0) + 1
        print("[%s] %s (%s) → %s | %s" % ("验活", sess["cred_id"], sess.get("role"),
                                          new_status, reason))
    if args.write:
        vault.save_sessions(paths, doc)
        print("[回写] cred/sessions.json 已更新")
    print("[汇总] alive=%d expired=%d unknown=%d revoked=%d（本次续期成功 %d）"
          % (stat["alive"], stat["expired"], stat["unknown"], stat["revoked"], stat["renewed"]))
    if stat["alive"] == 0:
        print("[警告] 当前无可消费身份！挖掘门禁 cred_gate 将阻断。请补充凭据或调度 cred-steward。")


if __name__ == "__main__":
    main()
