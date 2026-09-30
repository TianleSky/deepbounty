# -*- coding: utf-8 -*-
"""导入阶段:把 Burp 导出的 XML 历史记录翻译为代理日志三件套(伪装成"代理已抓完包")。

产物(与 proxy/recorder.py 线上抓包口径完全一致,下游脚本零改动):
    proxy-logs/url_index.jsonl     成功请求(状态<400)的 URL 清单
    proxy-logs/failed_index.jsonl  失败请求(4XX/5XX/无响应)清单
    proxy-logs/requests/URL*.log   该 URL 全部原始请求报文(含响应头+文本类响应预览)
    proxy-logs/params/URL*.json    参数详情(仅成功且有参数)

复用策略:设置 PROXY_LOG_DIR 后 import recorder,实例化其 Recorder 作为日志目录状态机,
落盘/分类/幂等续跑全部走 recorder 原逻辑;参数提取用 recorder 的纯函数
(_flatten_json / _infer_scalar_type / _parse_multipart / _truncate)。

幂等续导:已存在的项目重复导入时,沿用既有 URL 编号、计数累加、参数只增不改。

用法:
    python import_burp.py --project <id> --file burp-export.xml [--file more.xml]
        [--data-root pentest-data] [--scope example.com] [--exclude ".../logout"] [--scope-regex]
"""

import argparse
import base64
import binascii
import json
import os
import re
import sys
import time
import zlib
import xml.etree.ElementTree as ET
from urllib.parse import parse_qsl, urlsplit, urlunsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

_MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
           "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}

# 网关逻辑接口分发字段白名单:header 小写比对;body 仅 JSON 顶层键。
# method 单独处理——仅当 body 同时含 "jsonrpc" 键(JSON-RPC 2.0)才认,防误伤普通业务字段。
_RPC_HEADER_FIELDS = ("operation-type", "x-operation-type")
_RPC_BODY_FIELDS = ("operationType", "operationName", "apiMethod", "interfaceName", "rpcName", "service")


# --------------------------- Burp 字段解析 ---------------------------

def _b64(text):
    """Burp 的 base64 文本(可能含空白换行)→ 字节;失败返回空。"""
    if not text:
        return b""
    t = re.sub(r"\s+", "", text)
    try:
        return base64.b64decode(t, validate=False)
    except binascii.Error:
        return b""


def _elem_bytes(elem):
    """request/response 元素:按 base64 属性还原原始字节。
    兼容两种导出命名:Burp「保存项目」用 base64encoded,部分版本/API 用 isBase64Encoded。"""
    if elem is None or elem.text is None:
        return b""
    flag = elem.get("base64") or elem.get("base64encoded") or elem.get("isBase64Encoded") or ""
    if flag.lower() == "true":
        return _b64(elem.text)
    return elem.text.encode("utf-8", "replace")


def _burp_time(s):
    """'Wed Sep 03 14:23:45 CST 2026' → 'YYYY-MM-DDTHH:MM:SS'(与 recorder 时间格式一致);失败用当前时间。"""
    try:
        p = (s or "").split()
        return "%04d-%02d-%02dT%s" % (int(p[5]), _MONTHS[p[1]], int(p[2]), p[3])
    except Exception:
        return time.strftime("%Y-%m-%dT%H:%M:%S")


def _split_head_body(raw):
    """原始报文 → (head_lines[list[bytes]], body[bytes])。兼容 CRLF/LF。"""
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        head, sep, body = raw.partition(b"\n\n")
    lines = head.split(b"\r\n") if b"\r\n" in head else head.split(b"\n")
    return lines, body


def _parse_headers(lines):
    """头行列表 → [(name, value)](保留顺序/大小写/重复头)。"""
    out = []
    for ln in lines:
        if b":" in ln:
            k, v = ln.split(b":", 1)
            out.append((k.decode("latin-1").strip(), v.decode("latin-1").strip()))
    return out


def _decompress(body, headers_pairs):
    """按 Content-Encoding 解压响应体(gzip/deflate/br);无法解压返回空(预览自动跳过)。"""
    ce = ""
    for k, v in headers_pairs:
        if k.lower() == "content-encoding":
            ce = v.lower()
            break
    if not body:
        return body
    try:
        if "gzip" in ce:
            return zlib.decompress(body, 16 + zlib.MAX_WBITS)
        if "deflate" in ce:
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
        if "br" in ce:
            import brotli  # 可选依赖
            return brotli.decompress(body)
    except Exception:
        return b""
    return body


# --------------------------- 喂给 Recorder 的轻量假对象 ---------------------------

class _Headers:
    """满足 recorder 的两个消费点:_headers_bytes(用 .fields,bytes 元组)与 .get()。"""

    def __init__(self, pairs):
        self.pairs = pairs or []

    @property
    def fields(self):
        return [(k.encode("utf-8", "replace"), v.encode("utf-8", "replace")) for k, v in self.pairs]

    def get(self, key, default=""):
        kl = key.lower()
        for k, v in self.pairs:
            if k.lower() == kl:
                return v
        return default


class _Req:
    """满足 recorder._append_raw:method / path(含query) / http_version / headers / content / url。"""

    def __init__(self, url, method, path, version, headers, content, host):
        self.url = url
        self.method = method
        self.path = path
        self.http_version = version
        self.headers = _Headers(headers)
        self.content = content
        self.pretty_host = host


class _Resp:
    """满足 recorder._append_raw/_response_preview:http_version / status_code / reason / headers / content(已解压)。"""

    def __init__(self, version, status_code, reason, headers, content):
        self.http_version = version
        self.status_code = status_code
        self.reason = reason
        self.headers = _Headers(headers)
        self.content = content


def _build_req(url, method_fallback, raw):
    """原始请求报文 → _Req。请求行 path 可能是绝对形式(代理风格),统一收敛为 origin-form。"""
    lines, body = _split_head_body(raw)
    method, path, version = method_fallback, urlsplit(url).path or "/", "HTTP/1.1"
    if lines:
        parts = lines[0].decode("latin-1").split(" ")
        if len(parts) >= 2:
            method, path = parts[0], parts[1]
            if len(parts) >= 3 and parts[2].startswith("HTTP/"):
                version = parts[2]
    if path.startswith("http://") or path.startswith("https://"):
        u = urlsplit(path)
        path = urlunsplit(("", "", u.path or "/", u.query, ""))
    u = urlsplit(url)
    if u.query and "?" not in path:
        path = path + "?" + u.query
    return _Req(url, method, path, version, _parse_headers(lines[1:] if lines else []), body,
                u.hostname or "")


def _build_resp(raw):
    """原始响应报文 → _Resp(body 已解压);空报文 → None。"""
    if not raw:
        return None
    lines, body = _split_head_body(raw)
    if not lines or not lines[0]:
        return None
    parts = lines[0].decode("latin-1").split(" ", 2)
    version = parts[0] if parts[0].startswith("HTTP/") else "HTTP/1.1"
    try:
        status_code = int(parts[1])
    except (IndexError, ValueError):
        return None
    reason = parts[2] if len(parts) > 2 else ""
    headers = _parse_headers(lines[1:])
    return _Resp(version, status_code, reason, headers, _decompress(body, headers))


def _detect_rpc(headers_pairs, body):
    """识别网关逻辑接口:header 白名单 + body JSON 白名单分发字段。
    返回 [(name, kind)];kind = rpc / graphql。无命中返回 []。"""
    out = []
    hl = {}
    for k, v in headers_pairs:
        hl[k.lower()] = v
    for f in _RPC_HEADER_FIELDS:
        v = (hl.get(f) or "").strip()
        if v and len(v) <= 200:
            out.append((v, "rpc"))
    ct = hl.get("content-type", "").lower()
    if body and ("json" in ct or body.lstrip()[:1] == b"{"):
        try:
            data = json.loads(body.decode("utf-8", "replace"))
        except Exception:
            data = None
        if isinstance(data, dict):
            for f in _RPC_BODY_FIELDS:
                v = data.get(f)
                if isinstance(v, str) and v.strip() and len(v) <= 200:
                    out.append((v.strip(), "graphql" if f == "operationName" else "rpc"))
            if "jsonrpc" in data:
                v = data.get("method")
                if isinstance(v, str) and v.strip() and len(v) <= 200:
                    out.append((v.strip(), "rpc"))
    return out


# --------------------------- 参数提取(recorder 纯函数 + 自有 body 解析) ---------------------------

def _extract_params(recorder, url, headers, body):
    """[(name, source, type, value)],覆盖 query / json / form / multipart。"""
    params = []
    try:
        for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            params.append((k, "query", recorder._infer_scalar_type(v), v))
    except Exception:
        pass

    ct = ""
    for k, v in headers:
        if k.lower() == "content-type":
            ct = v.lower()
            break
    if not body:
        return params
    try:
        if "application/json" in ct or "+json" in ct:
            data = json.loads(body.decode("utf-8", "replace"))
            for name, val, jtype in recorder._flatten_json(data):
                params.append((name, "json", jtype, recorder._json_value_str(val)))
        elif "x-www-form-urlencoded" in ct:
            for k, v in parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True):
                params.append((k, "form", recorder._infer_scalar_type(v), v))
        elif "multipart/form-data" in ct:
            for name, src, tp, val in recorder._parse_multipart(ct, body):
                params.append((name, src, tp, val))
    except Exception:
        pass
    return params


# --------------------------- 主流程 ---------------------------

def iter_burp_items(path):
    """iterparse 逐 item 产出 dict,内存友好(大 XML 不整体加载)。"""
    for _event, elem in ET.iterparse(path, events=("end",)):
        if elem.tag != "item":
            continue
        def txt(tag):
            e = elem.find(tag)
            return (e.text or "").strip() if e is not None else ""
        status = txt("status")
        yield {
            "time": txt("time"),
            "url": txt("url"),
            "method": txt("method"),
            "status": int(status) if status.isdigit() else None,
            "request": _elem_bytes(elem.find("request")),
            "response": _elem_bytes(elem.find("response")),
        }
        elem.clear()


def main():
    p = argparse.ArgumentParser(description="Burp XML 历史 → 代理日志三件套(伪装代理抓包,幂等续导)")
    p.add_argument("--project", required=True)
    p.add_argument("--file", required=True, action="append", help="Burp 导出 XML,可多次指定")
    p.add_argument("--data-root", default="pentest-data")
    p.add_argument("--scope", action="append", default=[], help="仅导入范围内请求(语法同代理 --scope)")
    p.add_argument("--exclude", action="append", default=[], help="范围内再排除(语法同代理 --exclude)")
    p.add_argument("--scope-regex", action="store_true")
    p.add_argument("--exclude-regex", action="store_true")
    p.add_argument("--scope-md", default="",
                   help="可选根域白名单 scope.md 路径。无限制原则：默认空=不启用、全量导入；"
                        "仅显式传入路径时才按白名单过滤")
    p.add_argument("--scope-engine", default=os.path.expanduser(r"~\.claude\skills\scope\engine"),
                   help="scope.py 引擎目录(默认 %(default)s)")
    p.add_argument("--keep-static", action="store_true",
                   help="保留纯静态资源(默认过滤:命中 .css/.png/.woff 等静态后缀的 URL 不导入)")
    args = p.parse_args()

    paths = c.project_paths(args.data_root, args.project)
    if not os.path.exists(paths["config"]):
        print("[提示] 项目未初始化,建议先运行 init_project.py --target <url> --project %s" % args.project)
    for key in ("proxy_logs",):
        os.makedirs(paths[key], exist_ok=True)
    os.makedirs(os.path.join(paths["proxy_logs"], "requests"), exist_ok=True)
    os.makedirs(os.path.join(paths["proxy_logs"], "params"), exist_ok=True)

    # 设置环境变量后再 import recorder:模块级 addons=[Recorder()] 会建目录,目标即本项目 proxy-logs,无害
    os.environ["PROXY_LOG_DIR"] = paths["proxy_logs"]
    os.environ["PROXY_SCOPE"] = json.dumps(args.scope)
    os.environ["PROXY_EXCLUDE"] = json.dumps(args.exclude)
    os.environ["PROXY_SCOPE_REGEX"] = "1" if args.scope_regex else "0"
    os.environ["PROXY_EXCLUDE_REGEX"] = "1" if args.exclude_regex else "0"
    sys.path.insert(0, os.path.join(SCRIPT_DIR, "proxy"))
    import recorder

    R = recorder.Recorder()  # rehydrate 既有清单,编号沿用、计数累加(幂等续导)

    # 无限制原则：默认不启用 scope.md 白名单，全量导入
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

    stats = {"items": 0, "skipped_scope": 0, "skipped_static": 0, "skipped_bad": 0,
             "success": 0, "failed": 0}
    rpc_found = {}  # name -> {"kind":..., "sources": set()}  逻辑接口(网关分发字段命中)
    for f in args.file:
        if not os.path.exists(f):
            print("[错误] 文件不存在:%s" % f)
            continue
        for item in iter_burp_items(f):
            stats["items"] += 1
            url = item["url"]
            if not url or not item["request"]:
                stats["skipped_bad"] += 1
                continue
            u = urlsplit(url)
            path_key = urlunsplit((u.scheme, u.netloc, u.path or "/", "", ""))
            if md_checker is not None and not md_checker(path_key):
                stats["skipped_scope"] += 1
                continue
            if not R._in_scope(path_key, u.hostname or ""):
                stats["skipped_scope"] += 1
                continue
            # 纯静态资源默认过滤(口径与 recorder._STATIC_EXT_RE 一致;动态端点如 captcha.php 不受影响)
            last_seg = (u.path or "/").rsplit("/", 1)[-1]
            if not args.keep_static and recorder._STATIC_EXT_RE.search(last_seg):
                stats["skipped_static"] += 1
                continue

            ts = _burp_time(item["time"])
            req = _build_req(url, item["method"] or "GET", item["request"])
            resp = _build_resp(item["response"])
            errored = resp is None
            is_success = resp is not None and resp.status_code < 400

            code = R.codes.get(path_key)
            if code is None:
                code = R._next_code()
                R.codes[path_key] = code
            R.totals[path_key] = R.totals.get(path_key, 0) + 1
            seq = R.totals[path_key]

            R._append_raw(code, seq, ts, req, resp, errored)

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
                for name, source, ptype, value in _extract_params(
                        recorder, url, req.headers.pairs, req.content):
                    key = (source, name)
                    if key not in rec.params:
                        rec.params[key] = {
                            "name": name, "source": source, "type": ptype,
                            "sample_value": recorder._truncate(value, R.value_cap),
                        }
                # 逻辑接口识别:命中分发字段即登记(保证网关上每个 operation 独立进账、独立被审计)
                for rpc_name, rpc_kind in _detect_rpc(req.headers.pairs, req.content):
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

    # 逻辑接口清单:js-rpc-apis.json(与 extract_rpc_apis.py 同格式;从真实请求抽出,seen_in_proxy 恒 true)
    # 幂等 upsert:已有 name 合并 sources,不覆盖既有记录。
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

    print("[完成] 导入 → %s" % paths["proxy_logs"])
    print("       item 总数 %(items)d;成功 %(success)d;失败 %(failed)d;"
          "范围外跳过 %(skipped_scope)d;静态过滤 %(skipped_static)d;无效跳过 %(skipped_bad)d" % stats)
    print("       成功 URL %d 个;失败 URL %d 个;编号已用至 URL%05d"
          % (len(R.success), len(R.failed), R.next_seq - 1))
    if rpc_found:
        print("       逻辑接口 %d 个(网关分发字段)→ js-rpc-apis.json" % len(rpc_found))
    print("[下一步] python build_url_inventory.py --project %s --data-root %s"
          % (args.project, args.data_root))


if __name__ == "__main__":
    main()
