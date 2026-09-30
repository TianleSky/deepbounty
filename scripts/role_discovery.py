# -*- coding: utf-8 -*-
"""DeepBounty 角色面发现器（role discovery）：回答"系统里有几种人、每种人覆盖了没有"。

修凭据链断点：role 全靠用户下发指定，众接口中"哪些接口属于哪类角色"无人发现。
例：haodf 同 host 下 /userdoctor/showmydoctor（患者视角）与 /user/managepatientlist
（医生视角）混排——只带患者身份挖，医生端功能面整体失明。

三路信号：
1. URL 路径角色词典：路径段命中角色词（doctor/merchant/admin/staff/seller/...），
   及语义对模式（my<Role>=该角色使用者；manage/list<Obj>+对象词=对象的管理方角色）。
2. 响应体角色字段：proxy-logs 响应预览中的 role/userType/identity/accountType 等
   字段及值分布（值分布提示"系统定义了几种身份"）。
3. 注册通道探测：register/signup 类 POST 接口 → 自助注册双号的候选入口。

产出 cred/roles.json：
- roles[]：每个角色的证据、关联 url_ids、已有 alive 身份覆盖、covered 判定
- registration_channels[]：自助注册候选入口（cred-steward 接码注册用）
- role_field_values：响应字段值分布（人工判读"1=患者 2=医生"用）
- url_role_map：url_id → 角色（miner 选身份用：测该 URL 优先带对应角色身份）

用法：
    python role_discovery.py --project <id> [--data-root pentest-data]
"""

import argparse
import os
import re
import sys
from collections import defaultdict
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c
import cred_vault as vault

# ---------- 角色词典 ----------

# 路径段直接角色词 → 规范角色名（中英文；命中即归该角色功能面）
ROLE_KEYWORDS = {
    # 管理/内部
    "admin": "admin", "administrator": "admin", "manage": "admin", "console": "admin",
    "backend": "admin", "backstage": "admin", "operator": "admin", "ops": "admin",
    "audit": "auditor", "auditor": "auditor",
    # 服务提供方（B 端/供给侧）
    "doctor": "doctor", "nurse": "staff", "staff": "staff", "employee": "staff",
    "merchant": "merchant", "seller": "merchant", "shop": "merchant", "store": "merchant",
    "vendor": "merchant", "supplier": "merchant", "agent": "agent", "broker": "agent",
    "enterprise": "enterprise", "company": "enterprise", "org": "enterprise",
    "tenant": "enterprise", "hr": "hr", "finance": "finance",
    "teacher": "teacher", "coach": "teacher", "driver": "driver", "rider": "rider",
    "anchor": "creator", "creator": "creator", "author": "creator", "up主": "creator",
    "kefu": "cs", "cs": "cs", "service": "cs",
    # 消费方（C 端）
    "patient": "patient", "buyer": "buyer", "customer": "user", "member": "member",
    "vip": "member", "student": "student", "parent": "parent", "passenger": "user",
    # 中文角色词
    "医生": "doctor", "患者": "patient", "商户": "merchant", "商家": "merchant",
    "卖家": "merchant", "买家": "buyer", "员工": "staff", "职员": "staff",
    "企业": "enterprise", "管理员": "admin", "客服": "cs", "会员": "member",
    "司机": "driver", "骑手": "rider", "老师": "teacher", "学生": "student",
}

# "manage<X>"/"<X>list" 模式：管理X → 我是 X 的管理方（如 managepatientlist→医生侧功能）
MANAGE_OBJ_TO_ROLE = {
    "patient": "doctor", "customer": "cs", "client": "staff", "order": "merchant",
    "goods": "merchant", "product": "merchant", "shop": "merchant", "student": "teacher",
    "employee": "hr", "staff": "admin", "user": "admin", "member": "admin",
    "driver": "admin", "case": "doctor", "appointment": "doctor",
}

# "my<X>" 模式（段内任意位置）：我的X → 我是 X 的持有对侧（如 showmydoctor→患者侧功能）
MY_OBJ_TO_HOLDER = {
    "doctor": "patient", "patient": "doctor", "teacher": "student", "student": "teacher",
    "order": "buyer", "goods": "buyer", "shop": "buyer", "merchant": "buyer",
    "driver": "user", "rider": "user", "case": "patient", "appointment": "patient",
    "coupon": "member", "point": "member", "wallet": "user", "favorite": "user",
}

# 子串匹配排除的泛词（独立成段才算数，子串命中噪音太大）
SUBSTR_SKIP = {"manage", "service", "console", "store", "shop", "org", "cs", "agent"}

# 响应体角色字段名（值分布 = 系统身份定义面）
ROLE_FIELDS = ("role", "roles", "roleid", "role_id", "rolecode", "role_code",
               "usertype", "user_type", "userrole", "user_role", "utype",
               "identity", "identities", "identitytype", "accounttype", "account_type",
               "membertype", "member_type", "grouptype", "tenanttype", "tenant_type",
               "isdoctor", "ispatient", "ismerchant", "isadmin", "isstaff", "isvip")

# 注册通道路径特征
REGISTER_RE = re.compile(r"(register|signup|sign_up|regist|enroll|openaccount|open_account"
                         r"|activate|join)(?!ed|ation)", re.I)
# 排除伪注册（ unregister / deregister 注销类）
UNREGISTER_RE = re.compile(r"(unregister|deregister|cancelaccount|closeaccount|deleteaccount)", re.I)

# 响应预览提取窗口（与 proxy-logs 的 200 字节预览对齐，宽松取前 4000 字符防字段截断）
RESP_PREVIEW_RE = re.compile(r"--- RESPONSE BODY \(preview[^\n]*\n(.*?)\n={5,}", re.S)


def _path_segments(url):
    try:
        path = urlsplit(url).path or ""
    except Exception:
        return []
    return [s for s in re.split(r"[/_.\-]+", path.lower()) if s]


def _match_role_by_path(url):
    """URL 路径 → [(role, evidence)]（按优先级排序：manage 语义 > my 语义 > 独立段词 > 子串词）。

    优先级案例（haodf 实测误判修正）：
    - managepatientlist：manage+patient→doctor（管理方），不是裸 manage→admin
    - showmydoctor：含 mydoctor→patient（我的医生=患者侧），不是裸 doctor→doctor
    """
    segs = _path_segments(url)
    hits = []
    for seg in segs:
        # 1. manage<X> 语义（最强：管理方角色）
        m = re.match(r"^(?:manage|admin)(\w+?)(?:list|manage|center|admin)?$", seg)
        if m and m.group(1) in MANAGE_OBJ_TO_ROLE:
            hits.append((MANAGE_OBJ_TO_ROLE[m.group(1)],
                         "path_manage_obj:%s→%s" % (seg, m.group(1))))
            continue  # 语义对命中后不再报裸关键词（防 manage→admin 误伤）
        # 2. my<X> 语义（段内任意位置：持有对侧）
        my_hit = False
        for mm in re.finditer(r"my(\w{3,})", seg):
            obj = mm.group(1)
            for tail in ("list", "center", "index", "info", "detail"):
                if obj.endswith(tail):
                    obj = obj[:-len(tail)]
                    break
            if obj in MY_OBJ_TO_HOLDER:
                hits.append((MY_OBJ_TO_HOLDER[obj],
                             "path_my_obj:%s（我的%s→%s侧）" % (seg, obj, MY_OBJ_TO_HOLDER[obj])))
                my_hit = True
                break
        if my_hit:
            continue
        # 3. 独立段关键词
        if seg in ROLE_KEYWORDS:
            hits.append((ROLE_KEYWORDS[seg], "path_keyword:%s" % seg))
            continue
        # 4. 复合段子串（排除泛词）
        for kw, role in ROLE_KEYWORDS.items():
            if len(kw) >= 4 and kw not in SUBSTR_SKIP and kw in seg and seg != kw:
                hits.append((role, "path_keyword_in:%s~%s" % (seg, kw)))
    # 去重保序
    seen, out = set(), []
    for role, ev in hits:
        if (role, ev) not in seen:
            seen.add((role, ev))
            out.append((role, ev))
    return out


def _scan_response_role_fields(log_path):
    """扫请求日志响应预览中的角色字段 → {field: set(values)}（每字段最多留 20 值）。"""
    found = defaultdict(set)
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return found
    for m in RESP_PREVIEW_RE.finditer(text):
        body = m.group(1)[:4000]
        for field in ROLE_FIELDS:
            for vm in re.finditer(r'"%s"\s*:\s*("([^"]{0,40})"|(\d{1,6})|(true|false))'
                                  % re.escape(field), body, re.I):
                val = vm.group(2) or vm.group(3) or vm.group(4) or ""
                if val and len(found[field]) < 20:
                    found[field].add(val)
    return found


def main():
    p = argparse.ArgumentParser(description="DeepBounty 角色面发现器")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    args = p.parse_args()

    paths = c.project_paths(args.data_root, args.project)
    inv = c.load_json(paths["inventory"], default={}) or {}
    urls = [u for u in inv.get("urls", []) if u.get("category") in ("page", "api")]
    sess_doc = vault.load_sessions(paths)
    alive = [s for s in sess_doc.get("sessions", [])
             if s.get("status") == "alive" and not s.get("is_anonymous")]

    # ---- 信号 1：URL 路径角色 ----
    role_urls = defaultdict(list)      # role → [(url_id, url, evidence)]
    url_role_map = {}                  # url_id → role（首个命中；多角色接口取首个，其余进 evidence）
    for u in urls:
        uid, url = u.get("id", ""), u.get("url", "")
        for role, ev in _match_role_by_path(url):
            role_urls[role].append((uid, url, ev))
            url_role_map.setdefault(uid, role)

    # ---- 信号 2：响应体角色字段 ----
    field_values = defaultdict(set)
    field_sources = defaultdict(set)   # field → url_ids
    req_dir = paths["requests_dir"]
    uid_by_log = {}
    if os.path.isdir(req_dir):
        for fn in os.listdir(req_dir):
            if fn.endswith(".log"):
                uid_by_log[fn[:-4]] = os.path.join(req_dir, fn)
    for u in urls:
        uid = u.get("id", "")
        lp = uid_by_log.get(uid)
        if not lp:
            continue
        for field, vals in _scan_response_role_fields(lp).items():
            field_values[field] |= vals
            field_sources[field].add(uid)

    # ---- 信号 3：注册通道 ----
    reg_channels = []
    for u in urls:
        url = u.get("url", "")
        path = (urlsplit(url).path or "").lower()
        if UNREGISTER_RE.search(path):
            continue
        if REGISTER_RE.search(path):
            methods = [m.upper() for m in (u.get("methods") or ["GET"])]
            reg_channels.append({
                "url_id": u.get("id", ""), "url": url, "methods": methods,
                "writable": "POST" in methods,
                "note": "自助注册候选入口；POST 者可由 cred-steward 走接码注册双号",
            })

    # ---- 覆盖对比：角色 → alive 身份 ----
    # 身份角色归一：sessions.role 与发现角色名直接比对；user/attacker/victim 视为 C 端泛角色；
    # userX- 前缀（历史双账号命名 userA-xxx/userB-xxx）同样视为 C 端泛角色
    c_end_generic = {"user", "attacker", "victim", "member", "buyer", "patient",
                     "student", "parent", "customer"}

    def _is_c_end(role_str):
        r = (role_str or "").lower()
        return r in c_end_generic or bool(re.match(r"^user[a-z]?[-_]", r))

    alive_by_role = defaultdict(list)
    alive_c_end = []
    for s in alive:
        r = (s.get("role") or "").lower()
        alive_by_role[r].append(s["cred_id"])
        if _is_c_end(r):
            alive_c_end.append(s["cred_id"])

    roles_out = []
    for role, items in sorted(role_urls.items()):
        url_ids = sorted({i[0] for i in items if i[0]})
        # 覆盖判定：精确角色有 alive；或该角色属 C 端泛角色且有任意 C 端 alive
        direct = list(alive_by_role.get(role, []))
        generic = []
        if role in c_end_generic or not direct:
            generic = [cid for r, cids in alive_by_role.items()
                       if r in c_end_generic and role in c_end_generic for cid in cids]
        covered_ids = sorted(set(direct) | set(generic if role in c_end_generic else []))
        roles_out.append({
            "role": role,
            "url_count": len(url_ids),
            "url_ids": url_ids[:50],
            "evidence": sorted({i[2] for i in items})[:10],
            "alive_cred_ids": covered_ids,
            "covered": bool(covered_ids),
            "coverage_note": ("有 %d 个 alive 身份" % len(covered_ids)) if covered_ids
                             else "无该角色 alive 身份：这些接口的该角色功能面测不了真实数据",
        })

    uncovered = [r["role"] for r in roles_out if not r["covered"]]

    doc = {
        "_note": "角色面发现（role_discovery 产出）：系统有几种人、每种人覆盖了没有。"
                 "miner 按 url_role_map 选身份；cred-steward 按 uncovered_roles + "
                 "registration_channels 补号",
        "roles": roles_out,
        "uncovered_roles": uncovered,
        "registration_channels": reg_channels,
        "role_field_values": {k: sorted(v) for k, v in sorted(field_values.items())},
        "role_field_sources": {k: sorted(v) for k, v in sorted(field_sources.items())},
        "url_role_map": url_role_map,
        "generated": c.now_iso(),
    }
    out_path = os.path.join(paths["cred_dir"], "roles.json")
    os.makedirs(paths["cred_dir"], exist_ok=True)
    c.atomic_write_json(out_path, doc)

    print("[角色面] 发现角色 %d 种：%s"
          % (len(roles_out), ", ".join(r["role"] for r in roles_out) or "无"))
    for r in roles_out:
        print("  %s %s：%d 个接口，覆盖=%s"
              % ("[OK]" if r["covered"] else "[缺]", r["role"], r["url_count"], r["covered"]))
    print("[注册通道] %d 个候选（POST 可写 %d 个）"
          % (len(reg_channels), sum(1 for x in reg_channels if x["writable"])))
    if field_values:
        print("[响应角色字段] %s"
              % ", ".join("%s=%s" % (k, sorted(v)[:6]) for k, v in sorted(field_values.items())))
    if uncovered:
        print("[未覆盖角色] %s → 列入 cred_gate 复核项；可走注册通道/用户补号" % ", ".join(uncovered))


if __name__ == "__main__":
    main()
