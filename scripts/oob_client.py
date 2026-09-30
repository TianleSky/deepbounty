# -*- coding: utf-8 -*-
"""DeepBounty OOB 带外通道客户端（interactsh 公共服封装）。

修复 tyang-skill2 "SSRF/盲注/盲 XSS/XXE 无带外通道 → 挖不到"的断点：
SSRF004 / XXE002 / CMDI002 / SQL004 等要点强制 OOB 确认。

封装本机 interactsh-client（projectdiscovery）为三个动作：
    start   后台启动长驻客户端（-json -o 落盘交互日志），取得会话域名
    new     为某次测试铸唯一子域 <label>.<domain>（label 即追溯键）
    poll    读交互日志，按 label 匹配是否收到带外交互（DNS/HTTP/SMTP）

用法：
    python oob_client.py --project <id> start [--client "D:\\...\\interactsh-client.exe"]
    python oob_client.py --project <id> new --label URL00012-ssrf1
    python oob_client.py --project <id> poll --label URL00012-ssrf1 [--wait 60]
    python oob_client.py --project <id> status
    python oob_client.py --project <id> stop
"""

import argparse
import json
import os
import random
import string
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c

DEFAULT_CLIENT = r"D:\Tools\AI\AIsrc\CyberStrikeAI\bin\interactsh-client.exe"


def _state_path(paths):
    return os.path.join(paths["oob_dir"], "current.json")


def _load_state(paths):
    return c.load_json(_state_path(paths), default=None)


def _save_state(paths, st):
    c.atomic_write_json(_state_path(paths), st)


def _find_client(args_client=""):
    if args_client and os.path.exists(args_client):
        return args_client
    if os.path.exists(DEFAULT_CLIENT):
        return DEFAULT_CLIENT
    # PATH 兜底
    import shutil
    return shutil.which("interactsh-client") or shutil.which("interactsh-client.exe")


def cmd_start(paths, args):
    st = _load_state(paths)
    if st and _pid_alive(st.get("pid")):
        print("[OOB] 已在运行：domain=%s pid=%s" % (st.get("domain"), st.get("pid")))
        return
    client = _find_client(args.client)
    if not client:
        print("[错误] 找不到 interactsh-client（--client 指定，或装 projectdiscovery interactsh-client）")
        sys.exit(1)
    os.makedirs(paths["oob_dir"], exist_ok=True)
    interactions = os.path.join(paths["oob_dir"], "interactions.jsonl")
    session_file = os.path.join(paths["oob_dir"], "session.yaml")
    payload_file = os.path.join(paths["oob_dir"], "payload.txt")
    stdout_log = os.path.join(paths["oob_dir"], "client-stdout.log")
    # 清空旧交互日志
    for fp in (interactions, payload_file):
        if os.path.exists(fp):
            os.remove(fp)
    cmd = [client, "-json", "-o", interactions, "-sf", session_file,
           "-psf", payload_file, "-n", "1", "-duc", "-pi", "5"]
    out = open(stdout_log, "w", encoding="utf-8")
    kwargs = {"stdout": out, "stderr": subprocess.STDOUT, "stdin": subprocess.DEVNULL}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000008  # DETACHED
    proc = subprocess.Popen(cmd, **kwargs)
    # 等 payload 域名出现（最多 30s）
    domain = ""
    for _ in range(30):
        time.sleep(1)
        if os.path.exists(payload_file):
            try:
                with open(payload_file, "r", encoding="utf-8", errors="replace") as f:
                    domain = f.read().strip().splitlines()[0].strip()
            except Exception:
                pass
        if not domain and os.path.exists(stdout_log):
            try:
                with open(stdout_log, "r", encoding="utf-8", errors="replace") as f:
                    txt = f.read()
                import re
                m = re.search(r"([a-z0-9]{20,}\.oast\.[a-z]+)", txt)
                if m:
                    domain = m.group(1)
            except Exception:
                pass
        if domain:
            break
    if not domain:
        print("[错误] OOB 客户端已启动但 30s 内未拿到会话域名，查 %s" % stdout_log)
        sys.exit(1)
    _save_state(paths, {"domain": domain, "pid": proc.pid, "client": client,
                        "interactions": interactions, "stdout": stdout_log,
                        "started": c.now_iso(), "labels": {}})
    print("[OOB] 已启动：domain=%s pid=%d" % (domain, proc.pid))
    print("      交互日志：%s" % interactions)


def _pid_alive(pid):
    if not pid:
        return False
    if os.name == "nt":
        r = subprocess.run(["tasklist", "/FI", "PID eq %s" % pid],
                           capture_output=True, text=True)
        return str(pid) in r.stdout
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def cmd_new(paths, args):
    st = _load_state(paths)
    if not st:
        print("[错误] OOB 未启动，先 start")
        sys.exit(1)
    label = args.label
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    fqdn = "%s.%s.%s" % (label.lower().replace("_", "-"), rand, st["domain"]) \
        if args.readable else "%s.%s" % (rand, st["domain"])
    st.setdefault("labels", {})[label] = {"fqdn": fqdn, "rand": rand, "created": c.now_iso()}
    _save_state(paths, st)
    print(fqdn)


def cmd_poll(paths, args):
    st = _load_state(paths)
    if not st:
        print("[错误] OOB 未启动")
        sys.exit(1)
    labels = st.get("labels", {})
    if args.label not in labels:
        print("[错误] 未知 label：%s（先 new）" % args.label)
        sys.exit(1)
    rand = labels[args.label]["rand"]
    deadline = time.time() + args.wait
    hits = []
    while True:
        hits = _scan_interactions(st["interactions"], rand)
        if hits or time.time() >= deadline:
            break
        time.sleep(5)
    if hits:
        print("[OOB 命中] label=%s 收到 %d 次带外交互：" % (args.label, len(hits)))
        for h in hits:
            print("  - %s %s from %s at %s" % (h.get("protocol"), h.get("full-id") or h.get("unique-id"),
                                               h.get("remote-address"), h.get("timestamp")))
        labels[args.label]["hits"] = hits
        _save_state(paths, st)
        sys.exit(0)
    print("[OOB 无交互] label=%s 等待 %ds 内未收到带外请求" % (args.label, args.wait))
    sys.exit(2)


def _scan_interactions(path, rand):
    hits = []
    if not os.path.exists(path):
        return hits
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or rand not in line:
                continue
            try:
                obj = json.loads(line)
                hits.append(obj)
            except Exception:
                hits.append({"raw": line})
    return hits


def cmd_status(paths):
    st = _load_state(paths)
    if not st:
        print("[OOB] 未启动")
        return
    alive = _pid_alive(st.get("pid"))
    print("[OOB] domain=%s pid=%s %s" % (st.get("domain"), st.get("pid"),
                                         "运行中" if alive else "已退出（需重新 start）"))
    print("      labels %d 个；交互日志 %s" % (len(st.get("labels", {})), st.get("interactions")))


def cmd_stop(paths):
    st = _load_state(paths)
    if st and st.get("pid"):
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(st["pid"]), "/F"], capture_output=True)
            else:
                os.kill(st["pid"], 9)
            print("[OOB] 已停止 pid=%s" % st["pid"])
        except Exception as e:
            print("[OOB] 停止异常：%s" % e)
    if st:
        st["pid"] = None
        _save_state(paths, st)


def main():
    p = argparse.ArgumentParser(description="DeepBounty OOB 带外通道（interactsh 封装）")
    p.add_argument("--project", required=True)
    p.add_argument("--data-root", default="pentest-data")
    sub = p.add_subparsers(dest="cmd", required=True)
    ps = sub.add_parser("start")
    ps.add_argument("--client", default="")
    pn = sub.add_parser("new")
    pn.add_argument("--label", required=True)
    pn.add_argument("--readable", action="store_true", help="子域带 label 前缀（默认纯随机更隐蔽）")
    pp = sub.add_parser("poll")
    pp.add_argument("--label", required=True)
    pp.add_argument("--wait", type=int, default=60)
    sub.add_parser("status")
    sub.add_parser("stop")
    args = p.parse_args()

    paths = c.project_paths(args.data_root, args.project)
    os.makedirs(paths["oob_dir"], exist_ok=True)
    if args.cmd == "start":
        cmd_start(paths, args)
    elif args.cmd == "new":
        cmd_new(paths, args)
    elif args.cmd == "poll":
        cmd_poll(paths, args)
    elif args.cmd == "status":
        cmd_status(paths)
    elif args.cmd == "stop":
        cmd_stop(paths)


if __name__ == "__main__":
    main()
