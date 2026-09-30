# -*- coding: utf-8 -*-
"""准备阶段：推导 project-id、建目录、登记 index.json、初始化 config.json / state.json。

幂等 + 断点：已存在同名项目则识别为「续测」并回报应跳转的阶段；target 冲突则报错。

用法：
    python init_project.py --target http://www.heasec.com:8080/ \
        [--project <id>] [--data-root pentest-data] [--proxy-port 24304]

无限制原则：不设安全边界/安全等级——config.json 的 scope/exclude 默认空（=不限制），
资产库项目即授权范围，全接口全操作放开。
"""

import argparse
import os
import re
import sys
from urllib.parse import urlsplit

import common as c

_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _SCRIPTS_DIR)


def derive_project_id(target):
    """从 target 的 hostname[:port] 推导：去用户信息、`.`/`:`→`-`、转小写。"""
    netloc = urlsplit(target).netloc or target
    netloc = netloc.split("@")[-1]
    return netloc.lower().replace(".", "-").replace(":", "-")


def main():
    p = argparse.ArgumentParser(description="威胁建模项目初始化（准备阶段）")
    p.add_argument("--target", required=True, help="目标根地址，如 http://www.heasec.com:8080/")
    p.add_argument("--project", default="", help="手动指定 project-id（默认由 target 推导）")
    p.add_argument("--data-root", default="pentest-data", help="数据根目录（默认 pentest-data）")
    p.add_argument("--proxy-port", type=int, default=24304, help="代理监听端口（默认 24304，写入 config.proxy_port）")
    args = p.parse_args()

    pid = args.project or derive_project_id(args.target)
    if not re.fullmatch(r"[a-z0-9-]+", pid):
        print("[错误] project-id 含非法字符（仅允许 a-z 0-9 -）：%s" % pid)
        print("       请用 --project 手动指定合法 id。")
        sys.exit(1)

    paths = c.project_paths(args.data_root, pid)
    idx_path = c.index_path(args.data_root)

    # 建目录（DeepBounty:纯导入流 + cred/memory/oob 子系统目录）
    for key in ("dir", "perm_dir", "reports_dir", "vuln_matrix_dir",
                "url_context_dir", "proxy_logs", "sessions_dir", "tmp_dir",
                "cred_dir", "memory_dir", "oob_dir"):
        os.makedirs(paths[key], exist_ok=True)

    idx = c.load_json(idx_path, default={"_note": "项目清单", "projects": []})
    existing = next((proj for proj in idx["projects"] if proj.get("project_id") == pid), None)
    now = c.now_iso()

    if existing is not None:
        if existing.get("target") != args.target:
            print("[冲突] 已存在同名 project-id 但 target 不同：")
            print("       已登记 target = %s" % existing.get("target"))
            print("       本次   target = %s" % args.target)
            print("       请用 --project 换一个 id。")
            sys.exit(1)
        existing["last_active"] = now
        c.atomic_write_json(idx_path, idx)
        state = c.load_json(paths["state"], default={"phase": existing.get("phase", 1)})
        phase = state.get("phase", 1)
        print("[续测] project-id = %s" % pid)
        print("       当前阶段 phase = %s（断点恢复，跳到对应阶段）" % phase)
        print("       配置文件：%s" % paths["config"])
        sys.exit(0)

    # 新建项目
    idx["projects"].append({
        "project_id": pid,
        "target": args.target,
        "dir": paths["dir"].replace("\\", "/"),
        "created": now,
        "last_active": now,
        "phase": 1,
        "status": "in_progress",
    })
    c.atomic_write_json(idx_path, idx)

    if not os.path.exists(paths["config"]):
        # 无限制原则：scope/exclude 默认空（=不限制），不写 security_level（已废弃）
        c.atomic_write_json(paths["config"], {
            "project_id": pid,
            "target": args.target,
            "scope": [],
            "exclude": [],
            "scope_regex": False,
            "exclude_regex": False,
            "test_accounts": [],
            "goals": "",
            "work_guidelines": "",
            "proxy_port": args.proxy_port,
            "oob_provider": "interactsh-public",
            "oob_endpoint": "",
            "leaf_budget": dict(c.DEFAULT_LEAF_BUDGET),
            "created": now,
            "notes": c.DEFAULT_NOTES,
        })
    if not os.path.exists(paths["state"]):
        c.atomic_write_json(paths["state"], {
            "phase": 1,
            "phase_status": {
                "import": "in_progress",
                "credentials": "pending",
                "task_tree": "pending",
                "vuln_mining": "pending",
                "validation": "pending",
                "retro": "pending",
            },
            "updated": now,
        })

    print("[新建] project-id = %s" % pid)
    print("       目录：%s" % paths["dir"])
    print("       配置：%s（无限制：scope/exclude 空=不限制；可补 test_accounts / goals）" % paths["config"])
    print("       当前阶段 phase = 1（准备阶段）")
    sys.exit(0)


if __name__ == "__main__":
    main()
