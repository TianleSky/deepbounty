# -*- coding: utf-8 -*-
r"""统一白名单维护:校验目标是否被 scope.md 覆盖;未覆盖则把根域追加进 In scope 列表(字母序)。

判定引擎复用 hunt 体系的 scope.py(deny-wins / default-deny / apex 含子域),不自造判定逻辑。
幂等:已被覆盖(含被父域覆盖)则不改文件;追加后重新判定确认生效。

用法:
    python ensure_scope.py alipay.com sub.aaaaa.com
    python ensure_scope.py https://www.aaaaa.com/path --md C:\path\to\scope.md
退出码:全部 IN-SCOPE 或成功 ADDED → 0;文件异常 → 1。
"""

import argparse
import os
import sys

DEFAULT_MD = r"C:\Users\Administrator\.claude\commands\scope.md"
DEFAULT_ENGINE = os.path.expanduser(r"~\.claude\skills\scope\engine")

# 常见双段公共后缀(宁保守;不在表内按末两段取根域)
_MULTI_SUFFIX = {
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "com.hk", "net.hk", "org.hk", "com.tw", "com.mo",
    "co.kr", "or.kr", "co.jp", "ne.jp", "co.uk", "org.uk",
    "com.au", "net.au", "com.sg", "com.my", "com.ph", "com.vn",
    "co.th", "co.in", "com.br", "com.mx", "com.tr",
}


def root_domain(host):
    """host → 注册根域(启发式:双段公共后缀取末三段,否则末两段)。"""
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return host.lower().strip(".")
    suf2 = ".".join(parts[-2:])
    if suf2 in _MULTI_SUFFIX and len(parts) >= 3:
        return ".".join(parts[-3:])
    return suf2


def add_to_md(md_path, root):
    """把 `- root` 按字母序插入 scope.md 的 '## In scope' 列表区。"""
    with open(md_path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    start = None
    for i, l in enumerate(lines):
        s = l.strip().lower()
        if s.startswith("##") and "in scope" in s and "out" not in s:
            start = i
            break
    if start is None:
        raise RuntimeError("scope.md 中未找到 '## In scope' 段")
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if lines[j].strip().startswith("## "):
            end = j
            break
    items = []
    for j in range(start + 1, end):
        s = lines[j].strip()
        if s.startswith("- "):
            items.append((j, s[2:].strip()))
    insert_at = None
    for j, val in items:
        if val.lower() > root:
            insert_at = j
            break
    if insert_at is None:
        insert_at = (items[-1][0] + 1) if items else (start + 1)
    lines.insert(insert_at, "- " + root)
    with open(md_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")


def main():
    p = argparse.ArgumentParser(description="scope.md 统一白名单:校验覆盖,未覆盖则追加根域(幂等)")
    p.add_argument("domains", nargs="+", help="域名 / 子域 / URL,可多个")
    p.add_argument("--md", default=DEFAULT_MD, help="scope.md 路径(默认 %(default)s)")
    p.add_argument("--engine", default=DEFAULT_ENGINE, help="scope.py 引擎目录(默认 %(default)s)")
    args = p.parse_args()

    if not os.path.exists(args.md):
        print("[错误] scope.md 不存在:%s" % args.md)
        sys.exit(1)
    sys.path.insert(0, args.engine)
    try:
        import scope as scope_engine
    except ImportError:
        print("[错误] 无法加载判定引擎 scope.py:%s" % args.engine)
        sys.exit(1)

    for d in args.domains:
        host = scope_engine._host_of(d)
        if not host:
            print("INVALID   %s(无法解析 host)" % d)
            continue
        scope = scope_engine._scope_from_md(args.md)
        if scope.in_scope_host(host):
            print("IN-SCOPE  %s(白名单已覆盖,不动)" % host)
            continue
        root = root_domain(host)
        add_to_md(args.md, root)
        # 复核:追加后必须命中
        scope2 = scope_engine._scope_from_md(args.md)
        ok = scope2.in_scope_host(host)
        print("ADDED     %s(根域 %s 已加入白名单%s)" % (host, root, "" if ok else ",但复核未命中,请检查!"))
        if not ok:
            sys.exit(1)


if __name__ == "__main__":
    main()
