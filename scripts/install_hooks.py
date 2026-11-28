#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""安装本仓 Git hooks（clone 后跑一次）。

    python scripts/install_hooks.py            # 写 core.hooksPath + 可执行位
    python scripts/install_hooks.py --check    # 只验收，不写配置
"""
import argparse
import os
import stat
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOKS = os.path.join(ROOT, ".githooks")
NAMES = ("pre-commit", "post-commit")


def current_hooks_path():
    r = subprocess.run(["git", "config", "--get", "core.hooksPath"],
                       cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
    return r.stdout.strip() if r.returncode == 0 else ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    if not os.path.isdir(os.path.join(ROOT, ".git")):
        print("[hooks] 非 git 仓库，跳过"); return 0
    missing = [n for n in NAMES if not os.path.isfile(os.path.join(HOOKS, n))]
    if missing:
        print("[hooks] FAIL 缺少钩子：" + ", ".join(missing), file=sys.stderr); return 1
    if args.check:
        cur = current_hooks_path()
        if cur != ".githooks":
            print("[hooks] FAIL core.hooksPath=%s，期望 .githooks" % (cur or "(未设置)"),
                  file=sys.stderr); return 1
        print("[hooks] OK core.hooksPath=.githooks，pre-commit / post-commit 就绪")
        return 0
    subprocess.run(["git", "config", "core.hooksPath", ".githooks"], cwd=ROOT, check=True)
    if os.name != "nt":
        for name in NAMES:
            path = os.path.join(HOOKS, name)
            os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    cur = current_hooks_path()
    if cur != ".githooks":
        print("[hooks] FAIL 写入后回读为 %s" % (cur or "(未设置)"), file=sys.stderr); return 1
    print("[hooks] 已配置 core.hooksPath=.githooks，提交时跑 pre-commit，提交后跑 post-commit 自动推")
    return 0


if __name__ == "__main__":
    sys.exit(main())
