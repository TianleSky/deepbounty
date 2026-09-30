# -*- coding: utf-8 -*-
"""把已通过审核的漏洞报告发布到飞书：云文档（含本地截图）+ 多维表格一行。

不参与挖掘，不改 review_status，不写入任何门禁。
发布技能收尾的最终报告：review_status=approved，或仍为 pending_review 但
validation/<vuln_id>/verdict.json 的 verdict 为 confirmed。rejected 不发。
已有 feishu_doc_url 时不重复建文档；表格按 VULN-VD号 搜索，有行则只补「飞书文档」，无行则新建。

用法：
    python publish_feishu.py --project <id> [--data-root pentest-data] [--vuln-id VULN-VD-...]
"""

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys

import common as c

BASE_TOKEN = "XxNlbBsMIaZpjusPAAzcCWRJnqg"
TABLE_ID = "tblZKX72Tt3vQsZZ"
DOC_FIELD = "飞书文档"
VD_FIELD = "VULN-VD号"

SEVERITY_CN = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
}

IMG_RE = re.compile(
    r"!\[([^\]]*)\]\((<[^>]+>|[^)\s]+)(?:\s+\"[^\"]*\")?\)"
)
FENCE_RE = re.compile(r"(```[\s\S]*?```)")
DATA_URI_RE = re.compile(
    r"^data:image/(png|jpeg|jpg|gif|webp);base64,([A-Za-z0-9+/=\s]+)$",
    re.I,
)


def lark_argv(args):
    """解析 lark-cli。Windows 的 npm 垫片是 .cmd，改走 node 直接执行，避免 cmd 吃掉参数。"""
    exe = shutil.which("lark-cli") or "lark-cli"
    if os.name == "nt":
        root = os.path.dirname(exe)
        js = os.path.join(root, "node_modules", "@larksuite", "cli", "scripts", "run.js")
        if os.path.isfile(js):
            node = os.path.join(root, "node.exe")
            if not os.path.isfile(node):
                node = shutil.which("node") or "node"
            return [node, js] + list(args)
        if exe.lower().endswith((".cmd", ".bat")):
            return ["cmd", "/c", exe] + list(args)
    return [exe] + list(args)


def run_lark(args, cwd, timeout=300):
    """执行 lark-cli。返回 (returncode, stdout, stderr)。"""
    cmd = lark_argv(args)
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            timeout=timeout,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        return 127, "", "未找到 lark-cli"
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        err = exc.stderr or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        if isinstance(err, bytes):
            err = err.decode("utf-8", "replace")
        return 124, out, err + "\n[超时] lark-cli %s" % " ".join(args[:4])
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def parse_json(text):
    """从 CLI 输出里取出一个 JSON 对象。解析失败返回 None。"""
    raw = (text or "").strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    start = raw.find("{")
    if start < 0:
        return None
    try:
        obj, _ = json.JSONDecoder().raw_decode(raw[start:])
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def walk_values(obj, key):
    found = []

    def walk(node):
        if isinstance(node, dict):
            if key in node:
                found.append(node[key])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(obj)
    return found


def cell_text(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        for key in ("text", "value", "name", "link"):
            if key in value:
                return cell_text(value[key])
        return ""
    if isinstance(value, list):
        return " ".join(cell_text(item) for item in value).strip()
    return str(value).strip()


def heading_body(md, prefix):
    """取第一个包含 prefix 的二级标题正文，到下一个二级标题为止。"""
    lines = md.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.startswith("## ") and prefix in line:
            start = i + 1
            break
    if start is None:
        return ""
    body = []
    for line in lines[start:]:
        if line.startswith("## "):
            break
        body.append(line)
    return "\n".join(body).strip()


def one_paragraph(text, limit=1500):
    collapsed = re.sub(r"\s+", " ", text or "").strip()
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[:limit] + "…"


def extract_endpoint(md):
    """从 SRC提交稿抽取「方法 + URL」。抽不到返回空串。"""
    matched = re.search(r"漏洞\s*URL[^\n`]{0,40}`([^`]+)`", md)
    if not matched:
        matched = re.search(
            r"漏洞\s*URL[：:\s]+((?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+)",
            md,
            re.I,
        )
    if not matched:
        return ""
    return re.sub(r"\s+", " ", matched.group(1)).strip()


def safe_asset_name(index, src_path, ext_fallback):
    base = os.path.basename(src_path.replace("\\", "/")) or ("image.%s" % ext_fallback)
    base = re.sub(r"[^\w.\-]+", "_", base, flags=re.UNICODE).strip("._") or ("image.%s" % ext_fallback)
    if "." not in base and ext_fallback:
        base = "%s.%s" % (base, ext_fallback)
    return "%02d-%s" % (index, base)


def rewrite_images(md, report_dir, assets_dir):
    """把本地图复制进 assets，正文改成 @./assets/...。不改代码块。返回 (正文, 复制数, 跳过说明)。"""
    os.makedirs(assets_dir, exist_ok=True)
    copied = [0]
    notes = []

    def place_file(src, alt, ext):
        copied[0] += 1
        name = safe_asset_name(copied[0], src, ext)
        dest = os.path.join(assets_dir, name)
        shutil.copyfile(src, dest)
        caption = alt.strip() or os.path.splitext(name)[0]
        return "![%s](@./assets/%s)" % (caption, name)

    def replace_image(match):
        alt = match.group(1) or ""
        raw = match.group(2).strip()
        if raw.startswith("<") and raw.endswith(">"):
            raw = raw[1:-1].strip()
        lower = raw.lower()
        if lower.startswith("http://") or lower.startswith("https://"):
            return match.group(0)
        if lower.startswith("data:"):
            data_match = DATA_URI_RE.match(re.sub(r"\s+", "", raw))
            if not data_match:
                notes.append("Base64 未解码")
                return "（Base64 图片未上传：%s）" % (alt.strip() or "图片")
            ext = data_match.group(1).lower()
            if ext == "jpeg":
                ext = "jpg"
            try:
                blob = base64.b64decode(data_match.group(2), validate=False)
            except Exception:
                notes.append("Base64 解码失败")
                return "（Base64 图片未上传：%s）" % (alt.strip() or "图片")
            if not blob:
                notes.append("Base64 为空")
                return "（Base64 图片未上传：%s）" % (alt.strip() or "图片")
            copied[0] += 1
            name = safe_asset_name(copied[0], "image.%s" % ext, ext)
            with open(os.path.join(assets_dir, name), "wb") as handle:
                handle.write(blob)
            caption = alt.strip() or os.path.splitext(name)[0]
            return "![%s](@./assets/%s)" % (caption, name)
        if os.path.isabs(raw):
            src = raw
        else:
            src = os.path.normpath(os.path.join(report_dir, raw))
        if not os.path.isfile(src):
            notes.append(raw)
            label = alt.strip() or os.path.basename(raw) or "图片"
            return "（图片未找到：%s）" % label
        ext = os.path.splitext(src)[1].lstrip(".") or "png"
        return place_file(src, alt, ext)

    parts = FENCE_RE.split(md)
    rewritten = []
    for part in parts:
        if part.startswith("```"):
            rewritten.append(part)
        else:
            rewritten.append(IMG_RE.sub(replace_image, part))
    return "".join(rewritten), copied[0], notes


def stage_report(project_dir, vuln_id, report_path):
    """复制报告到 tmp/feishu/<vuln_id>/report.md，并改写本地图片。不改原始文件。"""
    stage = os.path.join(project_dir, "tmp", "feishu", vuln_id)
    if os.path.isdir(stage):
        shutil.rmtree(stage)
    assets = os.path.join(stage, "assets")
    os.makedirs(assets, exist_ok=True)
    with open(report_path, "r", encoding="utf-8") as handle:
        original = handle.read()
    rewritten, copied, notes = rewrite_images(original, os.path.dirname(report_path), assets)
    staged_md = os.path.join(stage, "report.md")
    with open(staged_md, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(rewritten)
    return stage, copied, notes


def auth_ok(cwd):
    code, out, err = run_lark(["auth", "status", "--json", "--verify"], cwd, timeout=60)
    payload = parse_json(out) or parse_json(err)
    if code == 0 and not (isinstance(payload, dict) and payload.get("ok") is False):
        return True, out
    print("[失败] 飞书未登录或授权无效。先执行：lark-cli auth status --json --verify")
    if out.strip():
        print(out.strip())
    if err.strip():
        print(err.strip())
    return False, out


def ensure_doc_field(cwd):
    """没有「飞书文档」列才创建。返回 (ok, message)。"""
    code, out, err = run_lark([
        "base", "+field-list",
        "--base-token", BASE_TOKEN,
        "--table-id", TABLE_ID,
        "--as", "user",
    ], cwd, timeout=60)
    payload = parse_json(out)
    if code != 0 or not isinstance(payload, dict) or payload.get("ok") is False:
        return False, "读取字段失败：%s" % ((err or out).strip()[:500])
    names = field_names(payload)
    if DOC_FIELD in names:
        return True, "已有列"
    payload_path = os.path.join(cwd, "field-create.json")
    with open(payload_path, "w", encoding="utf-8") as handle:
        json.dump({"name": DOC_FIELD, "type": "text", "style": {"type": "url"}}, handle, ensure_ascii=False)
    code, out, err = run_lark([
        "base", "+field-create",
        "--base-token", BASE_TOKEN,
        "--table-id", TABLE_ID,
        "--json", "@./field-create.json",
        "--as", "user",
    ], cwd, timeout=60)
    created = parse_json(out)
    if code != 0 or not isinstance(created, dict) or created.get("ok") is False:
        return False, "创建「飞书文档」列失败：%s" % ((err or out).strip()[:500])
    return True, "已新建列"


def field_names(obj):
    """只收集带 type 或 field_id 的字段名，避免把选项名当成列名。"""
    names = set()

    def walk(node):
        if isinstance(node, dict):
            name = node.get("name")
            if isinstance(name, str) and ("type" in node or "field_id" in node):
                names.add(name)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(obj)
    return names


def load_ndjson(path):
    rows = []
    if not os.path.isfile(path):
        return rows
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def records_matching(obj, vuln_id):
    """从 JSON 里取出 VULN-VD号 精确等于 vuln_id 的记录，不把别的 record_id 算进来。"""
    found = []

    def walk(node):
        if isinstance(node, dict):
            if cell_text(node.get(VD_FIELD)) == vuln_id and node.get("record_id"):
                found.append(node)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(obj)
    return found


def find_record(vuln_id, work_dir):
    """按 VULN-VD号 精确查找。返回 record_id 或空串。找不到不是错误。"""
    output = os.path.join(work_dir, "search-%s.ndjson" % re.sub(r"[^\w.\-]+", "_", vuln_id))
    if os.path.isfile(output):
        os.remove(output)
    code, out, err = run_lark([
        "base", "+record-search",
        "--base-token", BASE_TOKEN,
        "--table-id", TABLE_ID,
        "--keyword", vuln_id,
        "--search-field", VD_FIELD,
        "--field-id", VD_FIELD,
        "--format", "ndjson",
        "--output", os.path.basename(output),
        "--as", "user",
    ], work_dir, timeout=60)
    rows = load_ndjson(output)
    if not rows:
        payload = parse_json(out)
        if isinstance(payload, dict):
            rows = records_matching(payload, vuln_id)
    exact = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        rid = row.get("record_id") or ""
        text = cell_text(row.get(VD_FIELD))
        if text == vuln_id and rid:
            exact.append(rid)
    if code != 0 and not exact:
        raise RuntimeError("搜索表格失败：%s" % ((err or out).strip()[:500]))
    if len(exact) > 1:
        print("[提示] %s 命中 %d 行，只更新第一行 %s" % (vuln_id, len(exact), exact[0]))
    return exact[0] if exact else ""


def create_document(stage, title):
    code, out, err = run_lark([
        "docs", "+create",
        "--as", "user",
        "--doc-format", "markdown",
        "--title", title,
        "--content", "@./report.md",
    ], stage, timeout=300)
    payload = parse_json(out)
    if code != 0 or not isinstance(payload, dict) or payload.get("ok") is False:
        raise RuntimeError("创建云文档失败：%s" % ((err or out).strip()[:800]))
    document = ((payload.get("data") or {}).get("document") or {})
    url = document.get("url") or ""
    if not url:
        raise RuntimeError("创建云文档未返回 url，不写入假链接")
    warnings = (payload.get("data") or {}).get("warnings") or []
    if warnings:
        print("[提示] 文档创建有 warnings：%s" % json.dumps(warnings, ensure_ascii=False)[:500])
    return url


def record_id_from(payload):
    for value in walk_values(payload, "record_id_list"):
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item:
                    return item
                if isinstance(item, dict) and item.get("record_id"):
                    return item["record_id"]
    for value in walk_values(payload, "record_id"):
        if isinstance(value, str) and value:
            return value
    return ""


def write_json_arg(work_dir, name, obj):
    path = os.path.join(work_dir, name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(obj, handle, ensure_ascii=False)
    return "@./%s" % name


def upsert_row(work_dir, vuln_id, fields, doc_url, existing_id):
    link = doc_url
    if existing_id:
        payload_ref = write_json_arg(work_dir, "update-row.json", {
            "update_records": {existing_id: {DOC_FIELD: link}},
        })
        code, out, err = run_lark([
            "base", "+record-batch-update",
            "--base-token", BASE_TOKEN,
            "--table-id", TABLE_ID,
            "--json", payload_ref,
            "--as", "user",
        ], work_dir, timeout=60)
        payload = parse_json(out)
        if code != 0 or not isinstance(payload, dict) or payload.get("ok") is False:
            raise RuntimeError("更新表格失败：%s" % ((err or out).strip()[:800]))
        return existing_id
    row = dict(fields)
    row[DOC_FIELD] = link
    payload_ref = write_json_arg(work_dir, "create-row.json", {"create_records": [row]})
    code, out, err = run_lark([
        "base", "+record-batch-create",
        "--base-token", BASE_TOKEN,
        "--table-id", TABLE_ID,
        "--json", payload_ref,
        "--as", "user",
    ], work_dir, timeout=60)
    payload = parse_json(out)
    if code != 0 or not isinstance(payload, dict) or payload.get("ok") is False:
        raise RuntimeError("新建表格行失败：%s" % ((err or out).strip()[:800]))
    rid = record_id_from(payload)
    if not rid:
        print("[提示] %s 行已写入，但响应里没有 record_id" % vuln_id)
    return rid


def build_fields(project_id, report, md):
    severity = SEVERITY_CN.get(report.get("severity") or "")
    if not severity:
        raise RuntimeError("危害等级无法映射：%r" % report.get("severity"))
    harm = one_paragraph(heading_body(md, "危害说明"))
    if not harm:
        harm = one_paragraph(heading_body(md, "漏洞摘要")) or (report.get("title") or "")
    return {
        "标题": report.get("title") or report.get("vuln_id"),
        "漏洞类型": report.get("vuln_type") or "",
        "危害等级": [severity],
        "项目": project_id,
        "接口": extract_endpoint(md),
        "业务危害": harm,
        VD_FIELD: report.get("vuln_id"),
        "报告路径": "%s/%s" % (project_id, report.get("report_file") or ""),
        "状态": ["已确认可提交"],
        "发现时间": report.get("created") or c.now_iso(),
    }


def publish_one(project_id, project_dir, report, work_dir):
    vuln_id = report.get("vuln_id") or ""
    report_file = report.get("report_file") or ""
    report_path = os.path.join(project_dir, report_file)
    if not os.path.isfile(report_path):
        raise RuntimeError("报告文件不存在：%s" % report_file)
    with open(report_path, "r", encoding="utf-8") as handle:
        original_md = handle.read()
    fields = build_fields(project_id, report, original_md)
    url = (report.get("feishu_doc_url") or "").strip()
    if url:
        print("[跳过建文档] %s 已有 %s" % (vuln_id, url))
    else:
        stage, copied, notes = stage_report(project_dir, vuln_id, report_path)
        print("[暂存] %s 本地图片 %d 张%s" % (
            vuln_id, copied, ("，未解析 %d 处" % len(notes)) if notes else ""))
        url = create_document(stage, fields["标题"])
        report["feishu_doc_url"] = url
        report["feishu_published_at"] = c.now_iso()
        print("[文档] %s %s" % (vuln_id, url))
    record_id = find_record(vuln_id, work_dir)
    saved_id = upsert_row(work_dir, vuln_id, fields, url, record_id)
    report["feishu_doc_url"] = url
    if saved_id:
        report["feishu_record_id"] = saved_id
    report["feishu_published_at"] = report.get("feishu_published_at") or c.now_iso()
    action = "更新" if record_id else "新建"
    print("[表格] %s %s行 %s" % (vuln_id, action, saved_id or "(无 record_id)"))
    return url


def validation_confirmed(project_dir, vuln_id):
    """盲验证结论为 confirmed 时，这份就是技能的最终报告。"""
    path = os.path.join(project_dir, "validation", vuln_id, "verdict.json")
    if not vuln_id or not os.path.isfile(path):
        return False
    try:
        data = json.load(open(path, encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(data, dict) and data.get("verdict") == "confirmed"


def is_final_report(project_dir, report):
    """已通过审核，或待审核但盲验证已确认。已拒绝不发。"""
    status = report.get("review_status")
    if status == "rejected":
        return False
    if status == "approved":
        return True
    if status == "pending_review":
        return validation_confirmed(project_dir, report.get("vuln_id") or "")
    return False


def select_reports(project_dir, reports, vuln_id):
    if vuln_id:
        matched = [item for item in reports if item.get("vuln_id") == vuln_id]
        if not matched:
            raise SystemExit("[错误] 报告清单中没有 %s" % vuln_id)
        item = matched[0]
        if not is_final_report(project_dir, item):
            raise SystemExit("[跳过] %s 审核状态为 %s，且盲验证未确认，不发布" % (
                vuln_id, item.get("review_status")))
        return [item]
    return [item for item in reports if is_final_report(project_dir, item)]


def main():
    parser = argparse.ArgumentParser(description="把最终漏洞报告发布到飞书文档和多维表格")
    parser.add_argument("--project", required=True)
    parser.add_argument("--data-root", default="pentest-data")
    parser.add_argument("--vuln-id", default="", help="只发布这一份；缺省则发布全部最终报告")
    args = parser.parse_args()

    paths = c.project_paths(args.data_root, args.project)
    if not os.path.isdir(paths["dir"]):
        print("[错误] 项目目录不存在：%s" % paths["dir"])
        return 1
    vr = c.load_json(paths["vuln_reports"], default={"reports": []})
    reports = vr.setdefault("reports", [])
    try:
        chosen = select_reports(paths["dir"], reports, args.vuln_id.strip())
    except SystemExit as exc:
        print(exc)
        return 1
    if not chosen:
        print("[完成] 没有可发布的最终报告（approved，或盲验证 confirmed），未调用飞书")
        return 0

    work_dir = os.path.join(paths["dir"], "tmp", "feishu")
    os.makedirs(work_dir, exist_ok=True)
    ok, _ = auth_ok(work_dir)
    if not ok:
        print("[失败] 未写入飞书文档或表格")
        return 1
    field_ok, field_msg = ensure_doc_field(work_dir)
    if not field_ok:
        print("[失败] %s" % field_msg)
        return 1
    print("[字段] %s" % field_msg)

    failed = 0
    for report in chosen:
        vuln_id = report.get("vuln_id") or "(无编号)"
        try:
            publish_one(args.project, paths["dir"], report, work_dir)
        except Exception as exc:
            failed += 1
            print("[失败] %s %s" % (vuln_id, exc))
        c.atomic_write_json(paths["vuln_reports"], vr)
    print("[汇总] 发布 %d，失败 %d（失败不改变 review_status，不计入挖掘门禁）" % (len(chosen), failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
