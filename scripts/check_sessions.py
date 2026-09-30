# -*- coding: utf-8 -*-
"""会话验活 + 自动续期:带凭据重放只读探针判断登录态;失效先复放流量里的凭据发放接口自救,
自救不成才报人补包。

设计原则(Tyang 凭据"验/续/报"环节):
- **只重放只读请求**(GET/HEAD)做验活,不对生产目标做剥离实验/写操作重放;
- 判定看三重指纹:状态码 / 登录页特征(标题与关键字) / 最终 URL;
- **自动续期**:身份带有 token_endpoint(extract_credentials 从流量识别出的发放接口)时,
  失效先原样复放该接口——cookie 型从响应 Set-Cookie 合并新 cookie,body 型从响应 JSON 取
  token 字段写回原因子位置——再重验探针;活了即回写,不劳烦人;
- 未登录基线(s0)对同一探针重放——若**未登录也拿到已登录才有的数据**,自动记 threats.jsonl
  一条 pending(未授权访问线索,挖掘期优先确认);
- 自救失败的身份**静默降级**:login_status=failed 回写,挖掘调度跳过该身份的授权用例,
  **未登录面与其他存活身份继续挖,全程不中断、不叫用户**;下次导入新流量(含新登录态)时
  extract_credentials.py 幂等刷新凭据,身份自动复活,此前跳过的用例补测。

用法:
    python check_sessions.py --project <id> [--probe-url <url>] [--write] [--no-renew]
    --write 回写 sessions.json 的 login_status/auth;不加则只演练打印。
    --no-renew 关闭自动续期(只验活)。
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
import urllib.parse

import common as c

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"
_LOGIN_HINT = re.compile(r"(请登录|登录页|sign[ -]?in|log[ -]?in|unauthorized|未授权|请重新登录)", re.I)
_MAX_BODY = 65536


def _request(url, method="GET", headers=None, body=None, auth=None, timeout=15):
    """统一请求;返回 (status, final_url, body_prefix, set_cookies)。跟随重定向,记录最终 URL。"""
    data = body.encode("utf-8") if isinstance(body, str) and body else None
    req = urllib.request.Request(url, data=data, method=method if not data else (method or "POST"))
    req.add_header("User-Agent", _UA)
    req.add_header("Accept", "*/*")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    auth = auth or {}
    if auth.get("cookie"):
        req.add_header("Cookie", auth["cookie"])
    for k, v in (auth.get("headers") or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(_MAX_BODY)
            sc = {}
            for v in r.headers.get_all("Set-Cookie") or []:
                pair = v.split(";")[0]
                if "=" in pair:
                    cn, cv = pair.split("=", 1)
                    sc[cn.strip()] = cv.strip()
            return r.status, r.geturl(), raw.decode("utf-8", errors="replace")[:2048], sc
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(_MAX_BODY).decode("utf-8", errors="replace")[:2048]
        except Exception:
            raw = ""
        sc = {}
        try:
            for v in (e.headers.get_all("Set-Cookie") or []):
                pair = v.split(";")[0]
                if "=" in pair:
                    cn, cv = pair.split("=", 1)
                    sc[cn.strip()] = cv.strip()
        except Exception:
            pass
        return e.code, getattr(e, "url", url), raw, sc
    except Exception as e:
        return -1, url, "FETCH_ERROR: %s" % e, {}


def _fetch(url, auth, timeout=15):
    """带身份重放只读探针;返回 (status, final_url, body_prefix)。"""
    st, fu, body, _ = _request(url, method="GET", auth=auth, timeout=timeout)
    return st, fu, body


def _looks_logged_out(status, final_url, body, orig_url, base=None):
    """判定是否"未登录"。base=(st0,fu0,body0) 未登录基线响应(探针有意义时才传):
    与基线一致 → 该探针本就不区分登录态,不能判死(防止全站跳登录页的目标把
    匿名 cookie 误杀);与基线不同 → 凭据有独立效果,按特征判。"""
    base_same = (base is not None and base[0] == status
                 and base[1] == final_url and base[2][:200] == body[:200])
    if status in (401, 403):
        return not base_same
    if status in (301, 302, 303, 307, 308) and _LOGIN_HINT.search(final_url or ""):
        return not base_same
    if final_url and final_url != orig_url and _LOGIN_HINT.search(final_url):
        return not base_same
    if body and _LOGIN_HINT.search(body[:1024]) and status == 200 and len(body.strip()) < 400:
        # 短 200 响应且满屏登录提示(网关型"假 200"业务错误码也在这里体现为短 body)
        return not base_same
    return False


def _merge_cookie(cookie_str, new_pairs):
    """把新 cookie {名:值} 合并进 'a=1; b=2' 串(同名替换,新名追加);返回 (新串, 是否有变化)。"""
    items = []
    seen = {}
    for p in (cookie_str or "").split(";"):
        if "=" in p:
            k, v = p.split("=", 1)
            k = k.strip()
            if k in new_pairs:
                v = new_pairs[k]
                seen[k] = True
            items.append("%s=%s" % (k, v.strip()))
    for k, v in new_pairs.items():
        if k not in seen and not any(i.startswith(k + "=") for i in items):
            items.append("%s=%s" % (k, v))
    merged = "; ".join(items)
    return merged, merged != (cookie_str or "")


def _try_renew(s):
    """自动续期:复放 token_endpoint 取新凭据。成功返回新 auth dict,无新凭据/失败返回 None。"""
    ep = s.get("token_endpoint") or {}
    if not ep.get("url"):
        return None
    status, _, resp_body, set_cookies = _request(
        ep["url"], method=ep.get("method") or "GET",
        headers=ep.get("headers"), body=ep.get("body") or None, auth=s.get("auth"))
    if status == -1:
        return None
    auth = s.get("auth") or {}
    new_auth = {"cookie": auth.get("cookie", ""),
                "headers": dict(auth.get("headers") or {})}
    changed = False
    if ep.get("renew") == "cookie" and set_cookies:
        merged, chg = _merge_cookie(new_auth["cookie"], set_cookies)
        if chg:
            new_auth["cookie"] = merged
            changed = True
    elif ep.get("renew") == "body" and ep.get("field") and resp_body:
        try:
            obj = json.loads(resp_body)
        except Exception:
            obj = None
        val = ""
        if isinstance(obj, dict):
            # 浅层 + 常见嵌套一层(data/result)找字段
            for box in (obj, obj.get("data") if isinstance(obj.get("data"), dict) else {},
                        obj.get("result") if isinstance(obj.get("result"), dict) else {}):
                if isinstance(box, dict) and box.get(ep["field"]):
                    val = str(box[ep["field"]])
                    break
        if val:
            target = ep.get("target") or ""
            if target.startswith("cookie:"):
                merged, chg = _merge_cookie(new_auth["cookie"], {target.split(":", 1)[1]: val})
                if chg:
                    new_auth["cookie"] = merged
                    changed = True
            elif target:
                old = new_auth["headers"].get(target, "")
                prefix = "Bearer " if old.lower().startswith("bearer ") else ""
                if new_auth["headers"].get(target) != prefix + val:
                    new_auth["headers"][target] = prefix + val
                    changed = True
    return new_auth if changed else None


def main():
    p = argparse.ArgumentParser(description="会话验活:基线重放对比(只读请求)+ 失效自动续期自救")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    p.add_argument("--probe-url", default="", help="手动指定验活探针(覆盖 sessions.json 里的)")
    p.add_argument("--write", action="store_true", help="回写 sessions.json(login_status/自动刷新后的 auth)")
    p.add_argument("--no-renew", action="store_true", help="关闭自动续期(只验活)")
    args = p.parse_args()

    paths = c.project_paths(args.data_root, args.project)
    doc = c.load_json(paths["sessions"], default=None)
    if doc is None:
        print("[错误] 无 sessions.json(先跑 extract_credentials.py)")
        sys.exit(1)
    sess = doc.get("sessions", [])

    base = next((s for s in sess if s.get("role") == "unauthenticated"), None)
    identities = [s for s in sess if s.get("role") != "unauthenticated" and s.get("auth")]
    if not identities:
        print("[提示] 无有凭据身份可验。")
        sys.exit(0)

    stale = []   # 失效且自救失败的身份
    renewed = 0  # 自动续期成功数
    findings = []  # 疑似未授权线索
    for s in identities:
        probe = args.probe_url or s.get("probe_url") or ""
        if not probe:
            print("[%s] %s:无探针 URL(extract 时无 GET 样本)→ 跳过,需 --probe-url 人工指定"
                  % (s["session_id"], s["role"]))
            continue
        # 未登录基线先打(每身份一次):既用于"探针是否有区分度",也用于后面的未授权线索速查
        base_resp = _fetch(probe, {}) if base is not None else None
        status, final_url, body = _fetch(probe, s["auth"])
        alive = status != -1 and not _looks_logged_out(status, final_url, body, probe, base=base_resp)
        if not alive and not args.no_renew and (s.get("token_endpoint") or {}).get("url"):
            # 自动续期自救:复放流量里的凭据发放接口,拿新凭据再验一次
            new_auth = _try_renew(s)
            if new_auth:
                st2, fu2, body2 = _fetch(probe, new_auth)
                if st2 != -1 and not _looks_logged_out(st2, fu2, body2, probe, base=base_resp):
                    alive = True
                    renewed += 1
                    if args.write:
                        s["auth"] = new_auth
                        s["notes"] = "凭据已于 %s 经 token_endpoint 自动刷新" % c.now_iso()
                    print("      [自动续期] 复放 %s 取到新凭据,重验存活" % s["token_endpoint"]["url"][:70])
        mark = "success" if alive else "failed"
        base_same = (base_resp is not None and base_resp[0] == status
                     and base_resp[1] == final_url and base_resp[2][:200] == body[:200])
        tail = ""
        if alive and base_same:
            tail = " [注意:该探针未登录也同响应,无区分度——登录后流量含用户数据的 GET 更可靠]"
        print("[%s] %s → %s %s%s" % (s["session_id"], s["role"],
                                     "存活" if alive else "失效",
                                     "(HTTP %s)" % status if status != -1 else "(请求失败:%s)" % body[:60], tail))
        if args.write:
            s["login_status"] = mark
            s["last_check"] = c.now_iso()
            if not alive:
                s["notes"] = "验活失败(HTTP %s),自动续期%s,已降级静默;下次导入新流量自动恢复" % (
                    status, "无果" if (s.get("token_endpoint") or {}).get("url") else "不可用(无 token_endpoint)")
        if not alive:
            stale.append(s)
            continue

        # 未授权面速查:同一探针剥光凭据(基线)与已登录一致 → 线索
        if base_resp is not None:
            st0, fu0, body0 = base_resp
            if not _looks_logged_out(st0, fu0, body0, probe) and st0 == status and len(body0) > 64:
                # 未登录与已登录拿到同级响应 → 疑似未授权线索(保守:仅提示,由挖掘期确认)
                sim = (body0[:200] == body[:200])
                if sim:
                    findings.append(probe)
                    print("      [线索] 未登录基线响应与已登录一致 → 疑似未授权访问:%s(已记 threats.jsonl 待确认)" % probe)

    if args.write:
        c.atomic_write_json(paths["sessions"], doc)

    if findings:
        tpath = paths["threats"]
        existing = []
        if os.path.exists(tpath):
            with open(tpath, encoding="utf-8") as f:
                existing = [json.loads(l) for l in f if l.strip()]
        have = {t.get("name") for t in existing}
        for url in findings:
            name = "未授权访问线索-%s" % urllib.parse.urlsplit(url).path[:60]
            if name in have:
                continue
            existing.append({
                "id": c.next_id("THREAT", [t.get("id") for t in existing]),
                "name": name,
                "priority": "high",
                "related_objects": [url],
                "description": "验活时发现:未登录基线与已登录身份对同一探针响应一致(前 200 字节相同),疑似未授权访问。挖掘期优先确认。",
                "verification_status": "pending",
                "verification_report_id": "",
                "verification_detail": "",
                "notes": "check_sessions.py 自动登记",
                "created": c.now_iso(),
                "updated": c.now_iso(),
            })
        c.dump_jsonl(tpath, existing)

    if renewed:
        print("\n[自动续期] %d 个身份凭据已自动刷新%s" % (renewed, "并回写 sessions.json" if args.write else "(演练,未回写)"))
    if stale:
        # 静默降级(全程无接触):不生成"叫人补包"文件、不打断流程;状态就在 sessions.json 里,
        # 挖掘调度读 login_status 自行跳过;下次导入新流量时 extract 自动复活该身份。
        print("\n[降级] %d 个身份失效且自动续期无果 → 已标记 failed,挖掘跳过其授权用例,"
              "未登录面/其他身份继续;下次导入新流量将自动恢复(全程不中断)" % len(stale))
    elif not renewed:
        print("\n[验活完成] 全部身份存活。")


if __name__ == "__main__":
    main()
