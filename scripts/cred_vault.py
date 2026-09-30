# -*- coding: utf-8 -*-
"""DeepBounty 凭据库（cred vault）：账号注册表 + 会话池 v2 的统一 CRUD 与身份归并。

修复 tyang-skill2 凭据链 L1/L2/L3 断供：
- L1 导入即无凭据：匿名/设备指纹 Cookie（_did/did/kwpsecprodu 等）命中黑名单，不算身份。
- 身份爆炸：按 username / user_id / account_id 归并（不再按凭据值指纹分组，
  修 aliyun 122 / haodf 404 个假身份）；同账号换新凭据只刷新值，不新建身份。
- L3 零追溯：每个会话有稳定 cred_id，矩阵条目强制记录。

数据文件：
    cred/accounts.json   账号注册表（真实身份维度）
    cred/sessions.json   会话池（凭据维度，cred_id 稳定，status 状态机 unknown/alive/expired/revoked）

用法：
    python cred_vault.py --project <id> list
    python cred_vault.py --project <id> add-account --role attacker --username u1 --password *** [--hosts a.com,b.com]
    python cred_vault.py --project <id> add-session --account ACC0001 --cookie "S=1" [--header "Authorization: Bearer x"] --hosts a.com
    python cred_vault.py --project <id> add-packet --account ACC0001 --packet-file login_req.txt   # 登录请求包（重放续期用）
    python cred_vault.py --project <id> import-legacy            # 从根 sessions.json(extract_credentials 产物)归并导入
    python cred_vault.py --project <id> import-config            # 从 config.json.test_accounts 导入账号
    python cred_vault.py --project <id> bind-host CRED0001 --hosts a.com,b.com
    python cred_vault.py --project <id> mark CRED0002 --status revoked --note "用户告知已改密"
"""

import argparse
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c


# ---------- 加载 / 保存 ----------

def load_accounts(paths):
    return c.load_json(paths["cred_accounts"],
                       default={"_note": "账号注册表（按真实身份归并）", "accounts": []})


def save_accounts(paths, doc):
    c.atomic_write_json(paths["cred_accounts"], doc)


def load_sessions(paths):
    return c.load_json(paths["cred_sessions"],
                       default={"_note": "会话池 v2（仅 alive 可消费）", "sessions": []})


def save_sessions(paths, doc):
    c.atomic_write_json(paths["cred_sessions"], doc)


# ---------- 身份归并 ----------

def _norm(s):
    return (s or "").strip().lower()


def find_account(doc, username="", user_id="", role=""):
    """按 username / user_id 找已有账号（真实身份归并键）。命中返回账号 dict。"""
    for a in doc.get("accounts", []):
        if username and _norm(a.get("username")) and _norm(a.get("username")) == _norm(username):
            return a
        if user_id and _norm(a.get("user_id")) and _norm(a.get("user_id")) == _norm(user_id):
            return a
    return None


def add_account(doc, role, username="", password="", user_id="", hosts=None,
                source="user_provided", login_packet=None, notes=c.DEFAULT_NOTES):
    """新增或归并账号。返回 (account, created_new)。"""
    acc = find_account(doc, username=username, user_id=user_id)
    now = c.now_iso()
    if acc is not None:
        # 归并：只刷新，不改人工指定的 role
        if password:
            acc["password"] = password
        if hosts:
            acc["hosts"] = sorted(set(acc.get("hosts", [])) | set(hosts))
        if login_packet:
            acc["login_packet"] = login_packet
        acc["updated"] = now
        return acc, False
    aid = c.next_id("ACC", [a.get("account_id", "") for a in doc.get("accounts", [])], width=4)
    acc = {
        "account_id": aid,
        "role": role or "user",
        "username": username or "",
        "user_id": user_id or "",
        "password": password or "",
        "hosts": sorted(set(hosts or [])),
        "source": source,
        "login_packet": login_packet or {},
        "notes": notes,
        "created": now,
        "updated": now,
    }
    doc.setdefault("accounts", []).append(acc)
    return acc, True


# ---------- 匿名凭据判定 ----------

def _cookie_names(cookie_str):
    names = set()
    for part in (cookie_str or "").split(";"):
        if "=" in part:
            names.add(part.split("=", 1)[0].strip().lower())
    return names


def is_anonymous_auth(auth):
    """凭据是否仅为匿名/设备指纹 Cookie（无登录语义）。

    判定：无自定义认证头（Authorization/x-token 等），且 cookie 名全部命中黑名单
    （或 cookie 为空）→ 匿名。匿名凭据可作未登录基线，永不算"身份"。
    """
    auth = auth or {}
    headers = {k.lower(): v for k, v in (auth.get("headers") or {}).items()}
    auth_headers = [k for k in headers
                    if k in ("authorization", "x-token", "x-access-token", "token",
                             "x-auth-token", "x-api-key", "apikey", "x-session-token")]
    if auth_headers:
        return False
    names = _cookie_names(auth.get("cookie") or auth.get("cookie_value") or "")
    if not names:
        return True
    return names.issubset(c.ANON_COOKIE_NAMES)


# ---------- 会话 ----------

def _auth_fingerprint(auth):
    """凭据值指纹（仅用于同凭据去重刷新，不作身份归并键）。"""
    raw = json.dumps(auth or {}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:8]


def find_session(doc, account_id="", fingerprint=""):
    for s in doc.get("sessions", []):
        if account_id and s.get("account_id") == account_id:
            return s
        if fingerprint and s.get("fingerprint") == fingerprint:
            return s
    return None


def add_session(doc, account, auth, hosts=None, source="user_provided", probe_url=""):
    """为账号添加/刷新会话。返回 (session, created_new, is_anon)。"""
    anon = is_anonymous_auth(auth)
    fp = _auth_fingerprint(auth)
    now = c.now_iso()
    account_id = account.get("account_id", "") if account else ""
    sess = find_session(doc, account_id=account_id) if account_id else None
    if sess is None:
        sess = find_session(doc, fingerprint=fp)
    if sess is not None:
        # 归并刷新：凭据值更新、hosts 并集；状态重置待验活
        sess["auth"] = auth or {}
        sess["fingerprint"] = fp
        if hosts:
            sess["hosts"] = sorted(set(sess.get("hosts", [])) | set(hosts))
        sess["status"] = "unknown"
        sess["updated"] = now
        return sess, False, anon
    sid = c.next_id("CRED", [s.get("cred_id", "") for s in doc.get("sessions", [])], width=4)
    sess = {
        "cred_id": sid,
        "account_id": account_id,
        "role": (account or {}).get("role", "unauthenticated" if anon else "user"),
        "username": (account or {}).get("username", ""),
        "hosts": sorted(set(hosts or [])),
        "auth": auth or {},
        "fingerprint": fp,
        "is_anonymous": anon,
        "status": "unknown",
        "token_exp": "",
        "probe_url": probe_url or "",
        "verify": {},
        "token_endpoint": {},
        "source": source,
        "created": now,
        "updated": now,
        "notes": "匿名设备指纹凭据，仅作未登录基线" if anon else c.DEFAULT_NOTES,
    }
    doc.setdefault("sessions", []).append(sess)
    return sess, True, anon


# ---------- 子命令 ----------

def cmd_list(paths):
    accs = load_accounts(paths).get("accounts", [])
    sess = load_sessions(paths).get("sessions", [])
    print("[账号] %d 个：" % len(accs))
    for a in accs:
        print("  %s role=%s username=%s hosts=%s source=%s"
              % (a["account_id"], a.get("role"), a.get("username") or "-",
                 ",".join(a.get("hosts", [])) or "-", a.get("source")))
    print("[会话] %d 个：" % len(sess))
    for s in sess:
        anon = " [匿名]" if s.get("is_anonymous") else ""
        print("  %s acc=%s role=%s user=%s status=%s hosts=%s%s"
              % (s["cred_id"], s.get("account_id") or "-", s.get("role"),
                 s.get("username") or "-", s.get("status"),
                 ",".join(s.get("hosts", [])) or "-", anon))
    alive = [s for s in sess if s.get("status") == "alive" and not s.get("is_anonymous")]
    print("[汇总] 可消费(alive 非匿名)身份 %d 个" % len(alive))


def cmd_add_account(paths, args):
    doc = load_accounts(paths)
    hosts = [h.strip().lower() for h in (args.hosts or "").split(",") if h.strip()]
    acc, created = add_account(doc, role=args.role, username=args.username,
                               password=args.password, user_id=args.user_id,
                               hosts=hosts, source="user_provided")
    save_accounts(paths, doc)
    print("[%s] %s role=%s username=%s" % ("新建账号" if created else "归并刷新",
                                           acc["account_id"], acc["role"], acc["username"] or "-"))


def _parse_headers(header_list):
    out = {}
    for h in header_list or []:
        if ":" in h:
            k, v = h.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def cmd_add_session(paths, args):
    accs = load_accounts(paths)
    acc = None
    if args.account:
        acc = next((a for a in accs.get("accounts", []) if a.get("account_id") == args.account), None)
        if acc is None:
            print("[错误] 账号 %s 不存在，先 add-account" % args.account)
            sys.exit(1)
    elif args.username or args.role:
        acc, _ = add_account(accs, role=args.role or "user", username=args.username or "",
                             source="user_provided")
        save_accounts(paths, accs)
    auth = {"cookie": args.cookie or "", "headers": _parse_headers(args.header)}
    hosts = [h.strip().lower() for h in (args.hosts or "").split(",") if h.strip()]
    doc = load_sessions(paths)
    sess, created, anon = add_session(doc, acc, auth, hosts=hosts, source="user_provided")
    save_sessions(paths, doc)
    print("[%s] %s acc=%s status=unknown(待 cred_verify 验活)%s"
          % ("新建会话" if created else "归并刷新", sess["cred_id"],
             sess.get("account_id") or "-", " [匿名凭据,不算身份]" if anon else ""))


def cmd_add_packet(paths, args):
    """登记登录请求包（完整 HTTP 请求原文），供失效时重放续期。"""
    if not os.path.exists(args.packet_file):
        print("[错误] 请求包文件不存在：%s" % args.packet_file)
        sys.exit(1)
    with open(args.packet_file, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()
    packet = _parse_raw_request(raw)
    if not packet:
        print("[错误] 无法解析请求包（需要完整 HTTP 请求原文：请求行+头+body）")
        sys.exit(1)
    accs = load_accounts(paths)
    acc = next((a for a in accs.get("accounts", []) if a.get("account_id") == args.account), None)
    if acc is None:
        print("[错误] 账号 %s 不存在" % args.account)
        sys.exit(1)
    acc["login_packet"] = packet
    acc["updated"] = c.now_iso()
    save_accounts(paths, accs)
    print("[登录包] 已登记到 %s：%s %s（失效时 cred_verify 可重放续期）"
          % (args.account, packet.get("method"), packet.get("url")))


def _parse_raw_request(raw):
    """解析完整 HTTP 请求原文 → {method,url,headers,body}。"""
    m = re.match(r"(?s)^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP/[\d.]+\s*\n(.*?)\n\n?(.*)$",
                 raw.strip())
    if not m:
        return None
    method, path, head_block, body = m.group(1), m.group(2), m.group(3), m.group(4)
    headers = {}
    for ln in head_block.splitlines():
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip()] = v.strip()
    host = headers.get("Host") or headers.get("host") or ""
    url = path if "://" in path else ("https://%s%s" % (host, path))
    return {"method": method, "url": url, "headers": headers, "body": body or ""}


def cmd_import_config(paths):
    """从 config.json.test_accounts 导入账号（含 login_url → login_packet 占位）。"""
    cfg = c.load_json(paths["config"], default={}) or {}
    accs = load_accounts(paths)
    n_new = 0
    for ta in cfg.get("test_accounts", []) or []:
        _, created = add_account(
            accs, role=ta.get("role", "user"), username=ta.get("username", ""),
            password=ta.get("password", ""), source="config_test_accounts",
            login_packet={"url": ta.get("login_url", ""), "method": "POST",
                          "headers": {}, "body": ""} if ta.get("login_url") else None)
        n_new += 1 if created else 0
    save_accounts(paths, accs)
    print("[导入] config.test_accounts → 账号 %d 个（新增 %d）" %
          (len(cfg.get("test_accounts", []) or []), n_new))


# ---------- 从 proxy 流量提取多人凭据 ----------

# cookie 中的用户标识名（名命中即取值为身份键）
UID_COOKIE_NAMES = {"uid", "userid", "user_id", "mid", "member_id", "memberid",
                    "custid", "cust_id", "customer_id", "openid", "open_id",
                    "account_id", "passportid", "passport_id"}
# 数组式 cookie：userinfo[id]=xxx / user[uid]=xxx
ARRAY_UID_RE = re.compile(r"(?:^|;\s*)[^;=\s]+\[(?:id|uid|userid|user_id)\]=([^;\s]{4,64})", re.I)
# JWT payload 身份字段
JWT_UID_FIELDS = ("sub", "uid", "user_id", "userid", "mid", "openid", "jti")

_REQ_BLOCK_RE = re.compile(
    r"--- REQUEST ---\n([A-Z]+ \S+ HTTP/[\d.]+\n(?:[^\n]*\n)*?)(?:\n--- |\n={5,})")


def _uid_from_cookie(cookie_str):
    """从 Cookie 串提取用户标识（数组式优先，再标识名）。返回标识值或 ''。"""
    m = ARRAY_UID_RE.search(cookie_str or "")
    if m:
        return m.group(1)
    for part in (cookie_str or "").split(";"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        if k.strip().lower() in UID_COOKIE_NAMES:
            v = v.strip()
            if len(v) >= 4 and v.strip("0"):
                return v
    return ""


def _uid_from_jwt(headers):
    """Authorization: Bearer <JWT> → base64 解 payload 取身份字段（不验签）。"""
    import base64
    auth = ""
    for k, v in (headers or {}).items():
        if k.lower() == "authorization" and v.lower().startswith("bearer "):
            auth = v[7:].strip()
            break
    if not auth or auth.count(".") < 2:
        return ""
    try:
        payload = auth.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        obj = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8", "replace"))
        for f in JWT_UID_FIELDS:
            v = str(obj.get(f) or "")
            if len(v) >= 4:
                return v
    except Exception:
        pass
    return ""


def cmd_import_proxy(paths):
    """扫 proxy-logs/requests/*.log 提取多人凭据入库。

    归并键 = cookie/JWT 中的用户标识（uid/userinfo[id]/JWT sub...）：
    同一标识的多条请求归并为一个人（凭据值取最后出现）；无标识的请求跳过
    （无法证明是"人"，防 identity-xxxx 身份爆炸）。匿名黑名单过滤。
    """
    req_dir = paths["requests_dir"]
    if not os.path.isdir(req_dir):
        print("[跳过] 无 proxy-logs/requests 目录")
        return
    accs = load_accounts(paths)
    doc = load_sessions(paths)
    # 第一遍：标识 → 最新一份 auth（含 hosts）
    people = {}   # uid → {"auth":..., "hosts":set, "hits":int}
    n_no_uid, n_anon, n_req = 0, 0, 0
    for fn in sorted(os.listdir(req_dir)):
        if not fn.endswith(".log"):
            continue
        try:
            with open(os.path.join(req_dir, fn), "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        for m in _REQ_BLOCK_RE.finditer(text):
            n_req += 1
            block = m.group(1)
            headers = {}
            for ln in block.splitlines()[1:]:
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    headers[k.strip()] = v.strip()
            host = ""
            for k, v in headers.items():
                if k.lower() == "host":
                    host = v.lower()
            cookie = next((v for k, v in headers.items() if k.lower() == "cookie"), "")
            auth_headers = {k: v for k, v in headers.items()
                            if k.lower() in ("authorization", "x-token", "x-access-token",
                                             "token", "x-auth-token", "x-api-key",
                                             "x-session-token")}
            auth = {"cookie": cookie, "headers": auth_headers}
            uid = _uid_from_cookie(cookie) or _uid_from_jwt(headers)
            if not uid:
                n_no_uid += 1
                continue
            if is_anonymous_auth(auth):
                n_anon += 1
                continue
            e = people.setdefault(uid, {"auth": None, "hosts": set(), "hits": 0})
            e["auth"] = auth          # 同一人多次出现：凭据值取最后（最新）
            e["hits"] += 1
            if host:
                e["hosts"].add(host)
    # 第二遍：入库
    n_new, n_merged = 0, 0
    for uid, e in sorted(people.items()):
        acc, _ = add_account(accs, role="user", username=uid,
                             hosts=sorted(e["hosts"]), source="proxy_extract")
        sess, created, _ = add_session(doc, acc, e["auth"], hosts=sorted(e["hosts"]),
                                       source="proxy_extract")
        n_new += 1 if created else 0
        n_merged += 0 if created else 1
    save_accounts(paths, accs)
    save_sessions(paths, doc)
    print("[提取] 扫描请求 %d 条 → 识别 %d 个人（无标识跳过 %d 条，匿名跳过 %d 条）"
          % (n_req, len(people), n_no_uid, n_anon))
    for uid, e in sorted(people.items()):
        print("  [人] %s：%d 次出现，hosts=%s" % (uid, e["hits"], ",".join(sorted(e["hosts"])) or "-"))
    print("[入库] 新会话 %d，归并刷新 %d；status=unknown，须 cred_verify.py --write 验活后才可消费"
          % (n_new, n_merged))


def cmd_import_legacy(paths):
    """从根 sessions.json（extract_credentials.py 产物）归并导入。

    归并键 = username（非凭据值指纹）；仅匿名因子的身份跳过（记 1 个未登录基线即可）。
    """
    legacy = c.load_json(paths["sessions"], default={"sessions": []}) or {"sessions": []}
    accs = load_accounts(paths)
    doc = load_sessions(paths)
    n_in, n_anon, n_merged = 0, 0, 0
    for s in legacy.get("sessions", []):
        auth = s.get("auth") or {}
        if s.get("role") == "unauthenticated" or is_anonymous_auth(auth):
            n_anon += 1
            continue
        username = s.get("username") or ""
        acc, _ = add_account(accs, role=s.get("role") or "user", username=username,
                             hosts=s.get("hosts") or [], source="traffic_extract")
        sess, created, _ = add_session(doc, acc, auth, hosts=s.get("hosts") or [],
                                       source="traffic_extract",
                                       probe_url=s.get("probe_url", ""))
        if s.get("token_endpoint"):
            sess["token_endpoint"] = s["token_endpoint"]
        if s.get("token_exp"):
            sess["token_exp"] = s["token_exp"]
        n_in += 1 if created else 0
        n_merged += 0 if created else 1
    save_accounts(paths, accs)
    save_sessions(paths, doc)
    print("[导入] 旧会话池 %d 个身份 → 新会话 %d（归并刷新 %d）；跳过匿名/基线 %d"
          % (len(legacy.get("sessions", [])), n_in, n_merged, n_anon))
    print("[提示] 导入后 status=unknown，须 cred_verify.py 验活才可消费")


def cmd_bind_host(paths, args):
    doc = load_sessions(paths)
    sess = next((s for s in doc.get("sessions", []) if s.get("cred_id") == args.cred_id), None)
    if sess is None:
        print("[错误] 会话 %s 不存在" % args.cred_id)
        sys.exit(1)
    hosts = [h.strip().lower() for h in (args.hosts or "").split(",") if h.strip()]
    sess["hosts"] = sorted(set(sess.get("hosts", [])) | set(hosts))
    sess["updated"] = c.now_iso()
    save_sessions(paths, doc)
    print("[绑定] %s hosts=%s" % (args.cred_id, ",".join(sess["hosts"])))


def cmd_mark(paths, args):
    if args.status not in c.CRED_STATUS:
        print("[错误] status 须 ∈ %s" % sorted(c.CRED_STATUS))
        sys.exit(1)
    doc = load_sessions(paths)
    sess = next((s for s in doc.get("sessions", []) if s.get("cred_id") == args.cred_id), None)
    if sess is None:
        print("[错误] 会话 %s 不存在" % args.cred_id)
        sys.exit(1)
    sess["status"] = args.status
    sess["notes"] = args.note or sess.get("notes", c.DEFAULT_NOTES)
    sess["updated"] = c.now_iso()
    save_sessions(paths, doc)
    print("[标记] %s → %s" % (args.cred_id, args.status))


def main():
    p = argparse.ArgumentParser(description="DeepBounty 凭据库（账号归并 + 会话池 v2）")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list")

    pa = sub.add_parser("add-account")
    pa.add_argument("--role", required=True)
    pa.add_argument("--username", default="")
    pa.add_argument("--password", default="")
    pa.add_argument("--user-id", dest="user_id", default="")
    pa.add_argument("--hosts", default="")

    ps = sub.add_parser("add-session")
    ps.add_argument("--account", default="")
    ps.add_argument("--role", default="")
    ps.add_argument("--username", default="")
    ps.add_argument("--cookie", default="")
    ps.add_argument("--header", action="append")
    ps.add_argument("--hosts", default="")

    pp = sub.add_parser("add-packet")
    pp.add_argument("--account", required=True)
    pp.add_argument("--packet-file", required=True)

    sub.add_parser("import-config")
    sub.add_parser("import-legacy")
    sub.add_parser("import-proxy")

    pb = sub.add_parser("bind-host")
    pb.add_argument("cred_id")
    pb.add_argument("--hosts", required=True)

    pm = sub.add_parser("mark")
    pm.add_argument("cred_id")
    pm.add_argument("--status", required=True)
    pm.add_argument("--note", default="")

    args = p.parse_args()
    paths = c.project_paths(args.data_root, args.project)
    os.makedirs(paths["cred_dir"], exist_ok=True)

    if args.cmd == "list":
        cmd_list(paths)
    elif args.cmd == "import-config":
        cmd_import_config(paths)
    elif args.cmd == "import-legacy":
        cmd_import_legacy(paths)
    elif args.cmd == "import-proxy":
        cmd_import_proxy(paths)
    else:
        {"add-account": cmd_add_account, "add-session": cmd_add_session,
         "add-packet": cmd_add_packet, "bind-host": cmd_bind_host,
         "mark": cmd_mark}[args.cmd](paths, args)


if __name__ == "__main__":
    main()
