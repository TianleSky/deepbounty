# -*- coding: utf-8 -*-
"""导入阶段(资产库模式):从 SRC 资产库(PostgreSQL)endpoint 表提取接口,翻译为代理日志三件套。

数据源(默认 DSN,--dsn/--env SRCDB_DSN 可覆盖):
    host=127.0.0.1 port=15432 dbname=src user=src

两种提取模式(二选一,对应召唤提示词):
    --project-name <名称>  按 endpoint.project 精确提取(接口表格里的项目名称)
    --subdomain <主机名>   按 endpoint.host 提取该子域名的接口(先精确匹配;0 行时按
                           ".主机名" 后缀匹配更深层子域并提示)

产物与 import_burp.py 完全同口径(下游脚本零改动):
    proxy-logs/url_index.jsonl     成功请求(状态<400)+ 资产库静态接口 的 URL 清单
    proxy-logs/failed_index.jsonl  失败请求(4XX/5XX/无响应)清单
    proxy-logs/requests/URL*.log   该 URL 全部原始请求报文(含响应头+文本类响应预览)
    proxy-logs/params/URL*.json    参数详情(仅成功且有参数)

静态接口(kind=静态,无数据包)的处理——真实性原则:
    只按 DB 事实登记 URL(方法/路径来自 endpoint 表,类别归 api——表中行皆为接口),
    不伪造任何报文:<id>.log 里如实写 NO RESPONSE,index 行 status_codes 记
    {"no-response": n} 标记"未验证",挖掘期按活接口现测。
    静态行不参与参数提取与逻辑接口识别(无 query/body 可提)。

复用策略与 import_burp 相同:PROXY_LOG_DIR 指向本项目 proxy-logs 后实例化 recorder.Recorder
(幂等续导:编号沿用、计数累加、参数只增不改);报文解析/参数提取/逻辑接口识别直接复用
import_burp 的既有函数。

用法:
    python import_srcdb.py --project <id> --project-name 小红书
    python import_srcdb.py --project <id> --subdomain api.xiaohongshu.com
    python import_srcdb.py --list                    # 看资产库里现有项目名称与接口数
        [--data-root pentest-data] [--dsn "..."] [--scope-md ...]
"""

import argparse
import json
import os
import sys
from urllib.parse import urlsplit, urlunsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c
import import_burp as ib

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DSN = "host=127.0.0.1 port=15432 dbname=src user=src"

ENDPOINT_COLS = ("id, host, kind, method, path, request_url, request_query, request_headers, "
                 "request_body, response_status, response_headers, response_body, "
                 "captured_at, source, source_id, project")


def db_rows(dsn, where, params):
    """按条件取 endpoint 行(dict 列表,按 id 稳定排序)。"""
    import psycopg
    with psycopg.connect(dsn, connect_timeout=10) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT %s FROM endpoint WHERE %s ORDER BY id" % (ENDPOINT_COLS, where),
                        params)
            cols = [d.name for d in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]


def resolve_rows(dsn, args):
    """按模式解析出要导入的行;返回 (rows, mode_desc)。0 行时给出可操作的提示后退出。"""
    if args.list:
        rows = db_rows(dsn, "project IS NOT NULL", ())
        by_proj = {}
        for r in rows:
            by_proj[r["project"]] = by_proj.get(r["project"], 0) + 1
        total = db_rows(dsn, "TRUE", ())
        print("[资产库] endpoint 共 %d 条;有项目名的 %d 条:" % (len(total), len(rows)))
        for name, n in sorted(by_proj.items(), key=lambda kv: -kv[1]):
            print("       %-24s %5d 条" % (name, n))
        print("[提示] 无项目名的存量接口 %d 条,用 --subdomain <主机名> 按主机提取。" %
              (len(total) - len(rows)))
        sys.exit(0)

    if args.project_name:
        rows = db_rows(dsn, "project = %s", (args.project_name,))
        if not rows:
            like = "%" + args.project_name + "%"
            cand = db_rows(dsn, "project ILIKE %s", (like,))
            names = sorted({r["project"] for r in cand})
            print("[错误] endpoint.project 无精确等于 %r 的行。" % args.project_name)
            if names:
                print("       模糊候选(用其中一个重跑):%s" % " / ".join(names[:20]))
            else:
                print("       资产库里没有任何项目名与其相似;`--list` 查看现有项目。")
            sys.exit(1)
        return rows, "project=%s" % args.project_name

    host = args.subdomain.strip().lower().rstrip(".")
    rows = db_rows(dsn, "LOWER(host) = %s", (host,))
    mode = "host=%s" % host
    if not rows:
        rows = db_rows(dsn, "LOWER(host) LIKE %s", ("%." + host,))
        if rows:
            hosts = sorted({r["host"] for r in rows})
            mode = "host LIKE *.%s(精确无命中,后缀命中 %d 台主机)" % (host, len(hosts))
            print("[提示] 无 host 精确等于 %s 的接口;按后缀命中更深层子域 %d 台:%s"
                  % (host, len(hosts), ", ".join(hosts[:10]) + ("…" if len(hosts) > 10 else "")))
    if not rows:
        print("[错误] endpoint 表里没有 host 为 %s(含更深子域)的接口;`--list` 查看现有项目,"
              "或确认子域名拼写。" % host)
        sys.exit(1)
    return rows, mode


def _headers_pairs(text):
    """DB 里的头原文(一行一个 Key: Value)→ [(name, value)];保留顺序/重复头。"""
    out = []
    for ln in (text or "").splitlines():
        ln = ln.strip("\r")
        if ":" in ln:
            k, v = ln.split(":", 1)
            k, v = k.strip(), v.strip()
            if k:
                out.append((k, v))
    return out


def _row_url(row):
    """行 → 完整 URL:优先 request_url;缺则按 host+path 拼 https 补全。"""
    url = (row.get("request_url") or "").strip()
    if not url:
        path = row.get("path") or "/"
        if not path.startswith("/"):
            path = "/" + path
        url = "https://%s%s" % ((row.get("host") or "").strip(), path)
    if "://" not in url:
        url = "https://" + url
    return url


def row_to_flow(row):
    """endpoint 行 → (url, req, resp, errored, is_static)。

    动态行:按 DB 报文原样还原(req/resp;resp 缺状态码则 errored)。
    静态行:无包,只按 DB 事实造请求行(host/method/path 均来自表),resp=None。
    """
    url = _row_url(row)
    u = urlsplit(url)
    method = (row.get("method") or "GET").strip() or "GET"
    host = (u.hostname or "").lower()
    # path(含 query)从完整 URL 收敛,保证与 path_key/query 参数提取口径一致
    path = urlunsplit(("", "", u.path or "/", u.query, ""))

    headers_text = row.get("request_headers") or ""
    body = (row.get("request_body") or "").encode("utf-8", "replace")
    is_static = not headers_text and not body and row.get("response_status") is None \
        and (row.get("kind") or "").strip() == "静态"

    if is_static:
        req = ib._Req(url, method, path, "HTTP/1.1", [], b"", host)
        return url, req, None, True, True

    req = ib._Req(url, method, path, "HTTP/1.1", _headers_pairs(headers_text), body, host)
    status = row.get("response_status")
    if status is None:
        return url, req, None, True, False
    # DB 存的是已解压文本(body 列 TEXT),直接给 _Resp,避免按响应头 Content-Encoding 重复解压
    resp = ib._Resp("HTTP/1.1", int(status), "",
                    _headers_pairs(row.get("response_headers") or ""),
                    (row.get("response_body") or "").encode("utf-8", "replace"))
    return url, req, resp, False, False


def main():
    p = argparse.ArgumentParser(description="SRC 资产库(PostgreSQL)endpoint 表 → 代理日志三件套")
    p.add_argument("--project", default="", help="project-id(--list 模式可省)")
    p.add_argument("--project-name", default=None, help="按 endpoint.project 精确提取(项目名称)")
    p.add_argument("--subdomain", default=None, help="按 endpoint.host 提取该子域名的接口")
    p.add_argument("--list", action="store_true", help="列出资产库现有项目名称与接口数后退出")
    p.add_argument("--data-root", default="pentest-data")
    p.add_argument("--dsn", default=os.environ.get("SRCDB_DSN", DEFAULT_DSN),
                   help="PostgreSQL 连接串(默认 %(default)s)")
    p.add_argument("--scope-md", default="",
                   help="可选根域白名单 scope.md 路径。无限制原则：默认空=不启用、资产库项目全量导入；"
                        "仅显式传入路径时才按白名单过滤")
    p.add_argument("--scope-engine", default=os.path.expanduser(r"~\.claude\skills\scope\engine"),
                   help="scope.py 引擎目录(默认 %(default)s)")
    args = p.parse_args()

    rows, mode = resolve_rows(args.dsn, args)
    if not args.project:
        p.error("--project 必填(--list 模式除外)")

    paths = c.project_paths(args.data_root, args.project)
    if not os.path.exists(paths["config"]):
        print("[提示] 项目未初始化,建议先运行 init_project.py --target <主域> --project %s" % args.project)
    for key in ("proxy_logs",):
        os.makedirs(paths[key], exist_ok=True)
    os.makedirs(os.path.join(paths["proxy_logs"], "requests"), exist_ok=True)
    os.makedirs(os.path.join(paths["proxy_logs"], "params"), exist_ok=True)

    # 与 import_burp 同一套机制:PROXY_LOG_DIR 指向本项目,Recorder 幂等续导
    os.environ["PROXY_LOG_DIR"] = paths["proxy_logs"]
    os.environ["PROXY_SCOPE"] = json.dumps([])
    os.environ["PROXY_EXCLUDE"] = json.dumps([])
    os.environ["PROXY_SCOPE_REGEX"] = "0"
    os.environ["PROXY_EXCLUDE_REGEX"] = "0"
    sys.path.insert(0, os.path.join(SCRIPT_DIR, "proxy"))
    import recorder

    R = recorder.Recorder()

    # 无限制原则：默认不启用 scope.md 白名单，资产库项目全量导入
    md_arg = args.scope_md or ""
    md_checker = None
    if md_arg:
        md_path = os.path.abspath(md_arg)
        if not os.path.exists(md_path):
            print("[错误] --scope-md 文件不存在:%s" % md_path)
            sys.exit(1)
        sys.path.insert(0, args.scope_engine)
        try:
            import scope as scope_engine
        except ImportError:
            print("[错误] 无法加载 scope.py 引擎:%s" % args.scope_engine)
            sys.exit(1)
        _md_scope = scope_engine._scope_from_md(md_path)
        md_checker = _md_scope.in_scope_host
        print("统一白名单:%s(In-scope %d 条 / Out-of-scope %d 条)"
              % (md_path, len(_md_scope.in_scope), len(_md_scope.out_of_scope)))

    stats = {"rows": 0, "dynamic": 0, "static": 0, "skipped_scope": 0, "skipped_bad": 0,
             "success": 0, "failed": 0}
    rpc_found = {}  # name -> {"kind":..., "sources": set()}(与 import_burp 同格式)
    hosts_seen = set()
    scope_blocked_hosts = set()  # 白名单外主机(超量跳过时提示补白名单后重导)

    for row in rows:
        stats["rows"] += 1
        try:
            url, req, resp, errored, is_static = row_to_flow(row)
        except Exception:
            stats["skipped_bad"] += 1
            continue
        if not url or not req:
            stats["skipped_bad"] += 1
            continue
        u = urlsplit(url)
        if not u.netloc:
            stats["skipped_bad"] += 1
            continue
        hosts_seen.add((u.hostname or "").lower())
        path_key = urlunsplit((u.scheme, u.netloc, u.path or "/", "", ""))
        if md_checker is not None and not md_checker(path_key):
            stats["skipped_scope"] += 1
            scope_blocked_hosts.add((u.hostname or "").lower())
            continue
        if not R._in_scope(path_key, u.hostname or ""):
            stats["skipped_scope"] += 1
            scope_blocked_hosts.add((u.hostname or "").lower())
            continue

        ts = row["captured_at"].strftime("%Y-%m-%dT%H:%M:%S") if row.get("captured_at") \
            else c.now_iso()[:19]
        code = R.codes.get(path_key)
        if code is None:
            code = R._next_code()
            R.codes[path_key] = code
        R.totals[path_key] = R.totals.get(path_key, 0) + 1
        seq = R.totals[path_key]

        R._append_raw(code, seq, ts, req, resp, errored)

        if is_static:
            # 静态接口:DB 断言它是接口,按 api 进成功清单;如实标 no-response(未验证)
            stats["static"] += 1
            stats["success"] += 1
            rec = R.success.get(path_key)
            if rec is None:
                rec = recorder.UrlRecord(code, path_key)
                rec.first_seen = ts
                R.success[path_key] = rec
            rec.category = "api"
            rec.methods.add(req.method)
            rec.request_count += 1
            rec.add_status(None)
            if ts > rec.last_seen:
                rec.last_seen = ts
            continue

        stats["dynamic"] += 1
        is_success = resp is not None and resp.status_code < 400
        bucket = R.success if is_success else R.failed
        rec = bucket.get(path_key)
        if rec is None:
            rec = recorder.UrlRecord(code, path_key)
            rec.first_seen = ts
            bucket[path_key] = rec
        rec.methods.add(req.method)
        rec.request_count += 1
        if ts > rec.last_seen:
            rec.last_seen = ts
        if ts < rec.first_seen or not rec.first_seen:
            rec.first_seen = ts
        if resp is not None:
            rec.update_category(resp.headers.get("content-type", ""))
        if not is_success:
            rec.add_status(resp.status_code if resp is not None else None)

        if is_success:
            stats["success"] += 1
            for name, source, ptype, value in ib._extract_params(
                    recorder, url, req.headers.pairs, req.content):
                key = (source, name)
                if key not in rec.params:
                    rec.params[key] = {
                        "name": name, "source": source, "type": ptype,
                        "sample_value": recorder._truncate(value, R.value_cap),
                    }
            for rpc_name, rpc_kind in ib._detect_rpc(req.headers.pairs, req.content):
                e = rpc_found.setdefault(rpc_name, {"kind": rpc_kind, "sources": set()})
                e["sources"].add("proxy-logs/requests/%s.log" % code)
        else:
            stats["failed"] += 1

    # flush(与 recorder.done 同口径)
    if R.success:
        R._write_index(R.success, R.success_index)
    if R.failed:
        R._write_index(R.failed, R.failed_index)
    for rec in R.success.values():
        if rec.params:
            R._write_params(rec)

    # 逻辑接口清单 upsert(与 import_burp 同格式、同幂等语义)
    if rpc_found:
        rpc_path = os.path.join(paths["dir"], "js-rpc-apis.json")
        doc = c.load_json(rpc_path, default={"_note": "Burp 流量分发字段抽出的逻辑接口", "apis": []})
        by_name = {a.get("name"): a for a in doc.get("apis", [])}
        for name, e in sorted(rpc_found.items()):
            if name in by_name:
                cur = by_name[name]
                cur["sources"] = sorted(set(cur.get("sources", [])) | e["sources"])[:5]
                cur["seen_in_proxy"] = True
            else:
                doc["apis"].append({
                    "name": name, "kind": e["kind"],
                    "sources": sorted(e["sources"])[:5], "seen_in_proxy": True,
                })
        doc["count"] = len(doc["apis"])
        doc["seen"] = sum(1 for a in doc["apis"] if a.get("seen_in_proxy"))
        doc["missing"] = doc["count"] - doc["seen"]
        c.atomic_write_json(rpc_path, doc)

    print("[完成] 资产库导入(%s)→ %s" % (mode, paths["proxy_logs"]))
    print("       endpoint 行 %(rows)d(动态 %(dynamic)d / 静态 %(static)d);"
          "成功 %(success)d;失败 %(failed)d;白名单外跳过 %(skipped_scope)d;无效跳过 %(skipped_bad)d" % stats)
    print("       涉及主机 %d 台;成功 URL %d 个;失败 URL %d 个;编号已用至 URL%05d"
          % (len(hosts_seen), len(R.success), len(R.failed), R.next_seq - 1))
    if rpc_found:
        print("       逻辑接口 %d 个(网关分发字段)→ js-rpc-apis.json" % len(rpc_found))
    if scope_blocked_hosts:
        shown = sorted(scope_blocked_hosts)
        print("       [提示] 白名单外被跳过的主机 %d 台:%s"
              % (len(shown), ", ".join(shown[:15]) + ("…" if len(shown) > 15 else "")))
        print("       无限制原则下默认全量导入；这些主机是因为显式传了 --scope-md 才被跳过。去掉该参数重跑即全量纳入。")
    print("[下一步] python build_url_inventory.py --project %s --data-root %s"
          % (args.project, args.data_root))


if __name__ == "__main__":
    main()
