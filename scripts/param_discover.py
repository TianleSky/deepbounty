# -*- coding: utf-8 -*-
"""DeepBounty 隐藏参数发现（Arjun 式，借 Agentic-Bug-Hunter /param-discover）。

对入库接口爆破常见隐藏参数名：候选参数以金丝雀值注入（GET→query，POST→body form），
与基线响应对比（状态码/长度/相似度），发现"参数被消费"的信号（响应变化/报错/新字段）。
发现的隐藏参数自动并入 proxy-logs/params/{URLID}.json 与 url-inventory.json（任务树重建即纳入）。

用法：
    python param_discover.py --project <id> --url-id URL00012 [--top 200] [--wordlist file]
    python param_discover.py --project <id> --all [--top 100]     # 全清单（慢，后台跑）
"""

import argparse
import difflib
import json
import os
import sys
import time
import urllib.parse
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c

# 内置高频隐藏参数字典（常见业务/调试/分页/排序/过滤参数）
BUILTIN_WORDLIST = """
id uid user_id userid account account_id username user name nickname mobile phone email
role admin is_admin type types category cat sort order orderby sortby field fields
page pages pageNum pageSize page_num page_size limit offset size per_page count
keyword keywords query q search s w wd key filter where condition
debug test dev trace verbose internal preview draft
callback cb jsonp format output render tpl template view layout
action act op method func function api service rpc operation operationType
token sign signature timestamp nonce appkey app_id appid secret key apikey api_key
version v ver lang language locale timezone
status state flag mode level grade vip
price amount money total fee discount coupon points credit balance
order_id orderNo order_no trade_no transaction_id product_id goods_id item_id sku
file filepath path filename dir download upload url link src target redirect next return_url
start end begin date time start_time end_time
group group_id org org_id dept dept_id company company_id tenant tenant_id
ids list data content text body remark desc description title
ext extra expand include exclude with
""".split()

CANARY = "dbx9z7q"
TIMEOUT = 12


def _http(url, method, params_in, headers=None, proxy=""):
    """params_in: dict 注入位置（query 或 form body）。返回 (status, body_bytes)。"""
    headers = dict(headers or {})
    headers.setdefault("User-Agent", "Mozilla/5.0 DeepBounty-ParamDiscover/1.0")
    if method == "GET":
        sep = "&" if "?" in url else "?"
        url = url + sep + urllib.parse.urlencode(params_in) if params_in else url
        data = None
    else:
        data = urllib.parse.urlencode(params_in).encode("utf-8")
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        handlers.append(urllib.request.HTTPSHandler(context=c.insecure_ssl_context()))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=TIMEOUT) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read()
        except Exception:
            return e.code, b""
    except Exception:
        return 0, b""


def discover_one(paths, url_rec, words, proxy="", delay=0.0):
    """对单个 URL 爆破隐藏参数。返回新发现参数名列表。"""
    uid = url_rec.get("id")
    url = url_rec.get("url", "")
    methods = url_rec.get("methods") or ["GET"]
    method = "POST" if "POST" in methods else "GET"
    known = set(url_rec.get("param_names") or [])

    base_s, base_b = _http(url, method, {}, proxy=proxy)
    if base_s == 0:
        print("[%s] 基线请求失败，跳过" % uid)
        return []
    base_len = len(base_b)

    found = []
    for w in words:
        if w in known:
            continue
        s, b = _http(url, method, {w: CANARY}, proxy=proxy)
        if delay:
            time.sleep(delay)
        if s == 0:
            continue
        # 信号：状态码变化 / 长度显著变化 / 相似度低 / 金丝雀回显
        sim = difflib.SequenceMatcher(None, base_b[:4096], b[:4096]).quick_ratio() if b else 0
        canary_echo = CANARY.encode() in b
        len_diff = abs(len(b) - base_len)
        if canary_echo or s != base_s or (base_len > 0 and len_diff > max(64, base_len * 0.1)) or sim < 0.9:
            found.append({"name": w, "signal": "status %s→%s len %d→%d sim=%.2f echo=%s"
                          % (base_s, s, base_len, len(b), sim, canary_echo)})
    return found


def merge_params(paths, uid, found):
    """新发现参数并入 params/{uid}.json 与 url-inventory.json。"""
    if not found:
        return
    pfile = os.path.join(paths["params_dir"], "%s.json" % uid)
    doc = c.load_json(pfile, default={"params": []})
    plist = doc.get("params", []) if isinstance(doc, dict) else doc
    names = {p.get("name") for p in plist}
    for f in found:
        if f["name"] not in names:
            plist.append({"name": f["name"], "source": "hidden_discovery",
                          "type": "string", "sample_value": CANARY})
    c.atomic_write_json(pfile, {"params": plist} if isinstance(doc, dict) else plist)

    inv = c.load_json(paths["inventory"], default={"urls": []})
    for u in inv.get("urls", []):
        if u.get("id") == uid:
            u["param_names"] = sorted(set(u.get("param_names", [])) |
                                      {f["name"] for f in found})
    c.atomic_write_json(paths["inventory"], inv)


def main():
    p = argparse.ArgumentParser(description="DeepBounty 隐藏参数发现（Arjun 式）")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    p.add_argument("--url-id", default="", help="单个 URLID")
    p.add_argument("--all", action="store_true", help="全清单 page/api 都跑")
    p.add_argument("--top", type=int, default=200, help="字典截断条数")
    p.add_argument("--wordlist", default="", help="外部字典文件（每行一个参数名）")
    p.add_argument("--delay", type=float, default=0.0, help="请求间隔秒（防 WAF 频控）")
    p.add_argument("--proxy", default="")
    args = p.parse_args()

    paths = c.project_paths(args.data_root, args.project)
    cfg = c.load_json(paths["config"], default={}) or {}
    proxy = args.proxy or ("http://127.0.0.1:%s" % cfg.get("proxy_port", 24304))

    words = BUILTIN_WORDLIST[:]
    if args.wordlist and os.path.exists(args.wordlist):
        with open(args.wordlist, "r", encoding="utf-8", errors="replace") as f:
            words.extend([ln.strip() for ln in f if ln.strip()])
    words = list(dict.fromkeys(words))[:args.top]

    inv = c.load_json(paths["inventory"], default={"urls": []})
    targets = [u for u in inv.get("urls", []) if u.get("category") in ("page", "api")]
    if args.url_id:
        targets = [u for u in targets if u.get("id") == args.url_id]
        if not targets:
            print("[错误] %s 不在清单" % args.url_id)
            sys.exit(1)
    elif not args.all:
        print("[错误] 须指定 --url-id 或 --all")
        sys.exit(1)

    total_new = 0
    for u in targets:
        found = discover_one(paths, u, words, proxy=proxy, delay=args.delay)
        if found:
            merge_params(paths, u["id"], found)
            total_new += len(found)
            print("[%s] 新发现隐藏参数 %d 个：%s"
                  % (u["id"], len(found), ", ".join(f["name"] for f in found)))
        else:
            print("[%s] 无新发现（字典 %d 词）" % (u["id"], len(words)))
    print("[完成] 共新发现 %d 个隐藏参数；重建任务树（task_tree.py build）即纳入挖掘"
          % total_new)


if __name__ == "__main__":
    main()
