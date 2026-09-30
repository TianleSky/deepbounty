# -*- coding: utf-8 -*-
"""凭据提取:从导入流量(proxy-logs/requests/*.log)直接提取已登录认证因子,分组为身份,写 sessions.json。

核心思路:Burp 流量本身就是已登录的——Cookie/Authorization 就在请求包里,**不找登录口、不自动重登**。
- 每 URL 只取时间最新的一条请求(最新凭据最可能有效);
- 认证因子 = Cookie 头 / Authorization 头 / 常见自定义认证头白名单;
- 按因子指纹分组 = 身份(同一账号跨 host 的 SSO 天然归并;多账号流量自动分出多角色,供越权矩阵);
- JWT 自动解 payload 取 exp 算死期;
- 幂等:已有 sessions.json 时,已知指纹不覆盖(人工/子代理回填的 role/username/login_status 保留),
  新指纹追加;恒有 unauthenticated 基线(s0)。

用法:
    python extract_credentials.py --project <id> [--data-root pentest-data]
"""

import argparse
import base64
import hashlib
import json
import os
import re
import sys
from urllib.parse import urlsplit

import common as c

# 常见自定义认证头(小写,保守集合)
_AUTH_HEADERS = {
    "authorization", "x-token", "x-auth-token", "x-access-token", "x-api-key",
    "token", "ticket", "access-token", "x-session-token", "x-user-token",
}
# 探针优先:路径含用户特征 + GET
_PROBE_HINT = re.compile(r"(user|profile|account|member|mine|current|/me\b|info|center)", re.I)
# 探针排除:登录/登出/注册页——这些页未登录也 200,验活会误判存活
_PROBE_BAD = re.compile(r"(login|signin|sign-in|logout|signout|register|captcha|/error)", re.I)
_REC_RE = re.compile(r"^###### \[(\w+) #\d+\] (\S+) \| (\w+) (\S+) ######$")


def _parse_log(fp):
    """解析单个 requests/{id}.log,产出记录列表(按文件顺序)。

    每条记录:ts/method/url/headers(请求头小写)/body(请求体)/resp_cookies({名:值},来自
    Set-Cookie)/resp_preview(响应体预览文本)。响应信息用于识别"凭据发放接口"(自动续期用)。
    """
    recs = []
    cur = None
    mode = None  # None | "req_h" | "req_b" | "resp_h" | "resp_b"
    try:
        with open(fp, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = _REC_RE.match(line.rstrip("\n"))
                if m:
                    if cur:
                        recs.append(cur)
                    cur = {"id": m.group(1), "ts": m.group(2), "method": m.group(3),
                           "url": m.group(4), "headers": {}, "body": "",
                           "resp_cookies": {}, "resp_preview": ""}
                    mode = None
                    continue
                if cur is None:
                    continue
                s = line.rstrip("\n")
                if s == "--- REQUEST ---":
                    mode = "req_h"
                    continue
                if s == "--- RESPONSE HEADERS ---":
                    mode = "resp_h"
                    continue
                if s.startswith("--- RESPONSE BODY"):
                    mode = "resp_b"
                    continue
                if s.startswith("===="):
                    mode = None
                    continue
                if mode == "req_h":
                    if s == "":
                        mode = "req_b"  # 空行后是请求体
                    elif ": " in s:
                        k, v = s.split(": ", 1)
                        cur["headers"][k.strip().lower()] = v.strip()
                elif mode == "req_b":
                    cur["body"] = (cur["body"] + "\n" + s).strip() if cur["body"] else s
                elif mode == "resp_h":
                    if s.lower().startswith("set-cookie:"):
                        pair = s.split(":", 1)[1].strip().split(";")[0]
                        if "=" in pair:
                            cn, cv = pair.split("=", 1)
                            cur["resp_cookies"][cn.strip()] = cv.strip()
                elif mode == "resp_b":
                    cur["resp_preview"] += s + "\n"
        if cur:
            recs.append(cur)
    except OSError:
        pass
    return recs


def _auth_factors(headers):
    """提取认证因子 {名: 值};Cookie 整串算一个因子。"""
    out = {}
    for k, v in headers.items():
        if k == "cookie" and v:
            out["cookie"] = v
        elif k in _AUTH_HEADERS and v:
            out[k] = v
    return out


def _fingerprint(factors):
    h = hashlib.sha1()
    for k in sorted(factors):
        h.update(k.encode())
        h.update(b"\x00")
        h.update(factors[k].encode())
        h.update(b"\x00")
    return h.hexdigest()[:8]


_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

# 响应体预览里的 token 样字段(JSON 键 → 值):发放接口识别用
_TOKEN_FIELD_RE = re.compile(
    r'"(access_?token|refresh_?token|id_?token|token|session_?id|sessionid|ticket|jwt|st)"'
    r'\s*:\s*"([A-Za-z0-9_\-\.=+/]{8,})"', re.I)
# 复放发放接口时需要携带的非认证头(认证因子复放时从身份 auth 动态带,不固化进模板)
_REPLAY_HEADERS = {"content-type", "accept", "origin", "referer", "user-agent"}


def _cookie_names(cookie_str):
    return {p.split("=", 1)[0].strip() for p in (cookie_str or "").split(";") if "=" in p}


def _find_token_endpoint(recs, factors):
    """在该身份的全部 scope 内流量里找"凭据发放接口"(自动续期用),取时间最新的一条。

    两种型:
    - cookie 型:响应 Set-Cookie 的 cookie 名 ∩ 身份 cookie 名 ≠ ∅ → 复放该请求可拿新 cookie;
    - body 型:响应体预览 JSON 里 token 样字段的值出现在身份认证因子中 → 复放该请求,
      从响应 JSON 同名字段取新值,写回 target 指定的因子("cookie:NAME" 或头名)。
    返回 token_endpoint dict;找不到返回 {}。
    """
    cookie_names = _cookie_names(factors.get("cookie", ""))
    factor_vals = list(factors.values())
    best = None  # (ts, endpoint)
    for rec in recs:
        ep = None
        if rec["resp_cookies"] and cookie_names and (set(rec["resp_cookies"]) & cookie_names):
            ep = {"renew": "cookie", "field": "", "target": "cookie"}
        if ep is None and rec["resp_preview"]:
            best_hit = None  # (因子值占比, target, field)——占比最大的因子是身份主令牌
            for m in _TOKEN_FIELD_RE.finditer(rec["resp_preview"]):
                field, val = m.group(1), m.group(2)
                for pname, pval in factors.items():
                    if pname == "cookie":
                        for pair in pval.split(";"):
                            if "=" in pair:
                                cn, cv = pair.split("=", 1)
                                cv = cv.strip()
                                if cv == val:
                                    hit = (1.0, "cookie:%s" % cn.strip(), field)
                                elif len(cv) >= 16 and (cv in val or val in cv):
                                    hit = (0.5, "cookie:%s" % cn.strip(), field)
                                else:
                                    continue
                                if best_hit is None or hit[0] > best_hit[0]:
                                    best_hit = hit
                    elif val in pval:
                        hit = (len(val) / max(len(pval), 1), pname, field)
                        if best_hit is None or hit[0] > best_hit[0]:
                            best_hit = hit
            if best_hit:
                ep = {"renew": "body", "field": best_hit[2], "target": best_hit[1]}
        if ep and (best is None or rec["ts"] > best[0]):
            ep.update({
                "url": rec["url"], "method": rec["method"],
                "headers": {k: v for k, v in rec["headers"].items() if k in _REPLAY_HEADERS},
                "body": rec["body"], "sampled_at": rec["ts"],
            })
            best = (rec["ts"], ep)
    return best[1] if best else {}


def _jwt_exp(text):
    """在文本里找 JWT,解 payload 取 exp(秒级时间戳);找不到/解不出返回 None。"""
    m = _JWT_RE.search(text or "")
    if not m:
        return None
    try:
        payload = m.group(0).split(".")[1]
        payload += "=" * (-len(payload) % 4)
        obj = json.loads(base64.urlsafe_b64decode(payload))
        exp = obj.get("exp")
        return int(exp) if exp else None
    except Exception:
        return None


def _jwt_username(text):
    m = _JWT_RE.search(text or "")
    if not m:
        return ""
    try:
        payload = m.group(0).split(".")[1]
        payload += "=" * (-len(payload) % 4)
        obj = json.loads(base64.urlsafe_b64decode(payload))
        for k in ("name", "username", "uid", "sub", "user_id", "nick"):
            if obj.get(k):
                return str(obj[k])
    except Exception:
        pass
    return ""


def main():
    p = argparse.ArgumentParser(description="从导入流量提取已登录凭据 → sessions.json(幂等)")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    args = p.parse_args()

    paths = c.project_paths(args.data_root, args.project)
    req_dir = os.path.join(paths["proxy_logs"], "requests")
    if not os.path.isdir(req_dir):
        print("[错误] 无导入产物:%s(先跑 import_burp.py)" % req_dir)
        sys.exit(1)

    # 只关心 config.scope 内的 host——挖掘只测范围内目标,范围外域名(bing/广告追踪等)的
    # cookie 不是登录态,不收(防止"每个广告域一个假身份"的噪音)
    cfg = c.load_json(paths["config"], default={})
    scopes = cfg.get("scope", []) or []
    excludes = cfg.get("exclude", []) or []
    scope_re = bool(cfg.get("scope_regex"))
    excl_re = bool(cfg.get("exclude_regex"))

    # 1) 汇总:scope 内全部记录(发放接口识别要用);每 URL 取最新一条带认证因子的请求
    latest = {}   # url -> rec(最新)
    all_recs = []  # scope 内全部(含无认证因子的——发放接口本身可能是匿名可调用的)
    skipped_host = 0
    for fn in sorted(os.listdir(req_dir)):
        if not fn.endswith(".log"):
            continue
        for rec in _parse_log(os.path.join(req_dir, fn)):
            if scopes and not c.url_in_test_scope(rec["url"], scopes, excludes, scope_re, excl_re):
                skipped_host += 1
                continue
            rec["factors"] = _auth_factors(rec["headers"])
            all_recs.append(rec)
            if not rec["factors"]:
                continue
            if rec["url"] not in latest or rec["ts"] > latest[rec["url"]]["ts"]:
                latest[rec["url"]] = rec

    if skipped_host:
        print("       (scope 外域名请求已跳过 %d 条——那些不是测试目标的登录态)" % skipped_host)
    if not latest:
        print("[提示] 范围内流量均无认证因子(Cookie/Authorization/自定义认证头)。")
        print("       若目标确已登录,请重新导出包含登录后请求的 Burp XML 再导入;")
        print("       或确认目标本就是纯未授权面(直接进挖掘)。")

    # 2) 按指纹分组身份
    groups = {}  # fp -> {"factors":..., "hosts":set, "samples":[rec...], "latest_ts":str}
    for rec in latest.values():
        fp = _fingerprint(rec["factors"])
        g = groups.setdefault(fp, {"factors": rec["factors"], "hosts": set(), "samples": [], "latest_ts": ""})
        g["hosts"].add(urlsplit(rec["url"]).netloc)
        g["samples"].append(rec)
        g["latest_ts"] = max(g["latest_ts"], rec["ts"])

    # 3) 组装/合并 sessions.json
    doc = c.load_json(paths["sessions"], default={"sessions": []})
    sess = doc.setdefault("sessions", [])
    by_fp = {s.get("fingerprint"): s for s in sess if s.get("fingerprint")}
    if not any(s.get("role") == "unauthenticated" for s in sess):
        sess.insert(0, {
            "session_id": "s0", "role": "unauthenticated", "username": "",
            "login_status": "success", "auth": {}, "fingerprint": "",
            "storage_state_file": "", "probe_url": "", "token_endpoint": {},
            "created": c.now_iso(), "notes": "未登录基线,用于权限矩阵对照",
        })

    n_new = 0
    for fp, g in sorted(groups.items(), key=lambda kv: -len(kv[1]["samples"])):
        # 找凭据发放接口(自动续期端点):响应里发放过该身份正在用的 cookie/token 的那个请求
        token_ep = _find_token_endpoint(all_recs, g["factors"])
        # 选探针:GET + 用户特征路径优先,排除登录/登出类(未登录也 200,验活无区分度)
        gets = [r for r in g["samples"] if r["method"] == "GET"
                and not _PROBE_BAD.search(urlsplit(r["url"]).path)]
        probe = ""
        for cand in sorted(gets, key=lambda r: (not _PROBE_HINT.search(urlsplit(r["url"]).path), -len(r["url"]))):
            probe = cand["url"]
            break
        # JWT 死期/用户名
        allv = " ".join(g["factors"].values())
        exp = _jwt_exp(allv)
        uname = _jwt_username(allv)
        cookie = g["factors"].get("cookie", "")
        headers = {k: v for k, v in g["factors"].items() if k != "cookie"}
        auth = {}
        if cookie:
            auth["cookie"] = cookie
        if headers:
            auth["headers"] = headers

        if fp in by_fp:
            s = by_fp[fp]
            if s.get("auth") != auth:
                s["auth"] = auth                   # 凭据值刷新(续包场景),身份字段不动
                if s.get("login_status") == "failed":
                    s["login_status"] = "success"  # 失效身份自动复活(待 check_sessions 复验)
                    s["notes"] = "凭据已随新流量导入自动刷新(%s),降级解除" % c.now_iso()
            if probe and not s.get("probe_url"):
                s["probe_url"] = probe
            if token_ep:
                s["token_endpoint"] = token_ep     # 续期端点刷新(取流量里最新的)
            if exp:
                s["token_exp"] = exp
            s["updated"] = c.now_iso()
            continue

        n_new += 1
        s = {
            "session_id": "s%d" % len(sess),
            "role": "identity-%s" % fp,
            "username": uname,
            "login_status": "success",
            "auth": auth,
            "fingerprint": fp,
            "hosts": sorted(g["hosts"]),
            "probe_url": probe,
            "storage_state_file": "",
            "token_endpoint": token_ep,
            "created": c.now_iso(),
            "notes": "从导入流量提取(%d 个 URL,最新 %s),待 check_sessions 验活"
                     % (len(g["samples"]), g["latest_ts"]),
        }
        if exp:
            s["token_exp"] = exp
        sess.append(s)

    c.atomic_write_json(paths["sessions"], doc)

    # 4) 摘要
    print("[完成] sessions.json → %s" % paths["sessions"])
    print("       身份(有凭据) %d 个;本次新增 %d 个;另有 unauthenticated 基线" % (len(groups), n_new))
    import datetime
    for s in sess:
        if s.get("role") == "unauthenticated":
            continue
        exp = s.get("token_exp")
        exp_s = ""
        if exp:
            dt = datetime.datetime.fromtimestamp(exp, datetime.timezone.utc).astimezone()
            left = exp - int(datetime.datetime.now().timestamp())
            exp_s = " | JWT 死期 %s(%s)" % (dt.strftime("%m-%d %H:%M"),
                                            "已过期!" if left < 0 else "剩 %d 小时" % (left // 3600))
        ep = s.get("token_endpoint") or {}
        renew_s = " | 可自动续期(%s)" % ep.get("renew", "") if ep.get("url") else ""
        print("       [%s] %s user=%r hosts=%d 探针=%s%s%s"
              % (s["session_id"], s["role"], s.get("username") or "?",
                 len(s.get("hosts", [])), (s.get("probe_url") or "无(需人工指定)")[:70], exp_s, renew_s))
    if groups:
        print("[下一步] python check_sessions.py --project %s --write  (验活并回写 login_status)" % args.project)


if __name__ == "__main__":
    main()
