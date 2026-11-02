#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
给 rootfs 瘦身（保留功能与合规所需的最小集合）
==============================================

删什么、为什么
--------------
| 路径 | 体积量级 | 理由 |
|---|---|---|
| /usr/share/man、/usr/share/info | 20–30 MB | 容器/终端环境里没人翻 man；命令本身还在 |
| /usr/share/doc/<pkg>/*（**保留 copyright**） | 10–15 MB | 文档正文可删，版权与许可声明必须留 |
| /usr/share/perl/*/pod、/usr/share/perl/*/…/perlpod | 10+ MB | perl 的 POD 文档；git 只用 perl 运行时 |
| /usr/local/lib/pythonX.Y/{test,idlelib,ensurepip,turtledemo} | 5–10 MB | 用不到；ensurepip 的轮子还占空间 |
| **/__pycache__、*.pyc | 数 MB | 首次导入会重新生成 |
| /usr/share/locale（除 C.UTF-8、zh_CN） | 5–10 MB | 保留中文与 C，其余删 |

不删什么
--------
- 任何 `*/copyright`：那是 Debian 的许可声明，删了不合规；
- `/usr/share/zoneinfo`：时区数据，办公场景常用；
- `/usr/lib/*/perl`、`/usr/lib/git-core`：功能本体。

用法
----
    python3 tools/slim-rootfs.py ROOTFS [--dry-run]

退出码
------
    0  成功
    1  目标不存在
    2  参数错误
"""

import argparse
import os
import shutil
import sys

# 整目录删
DROP_DIRS = [
    "usr/share/man",
    "usr/share/info",
    "usr/share/groff",
    "usr/share/lintian",
]

# 可整体删的 python 附带物（相对 /usr/local/lib/pythonX.Y 或 /usr/lib/pythonX）
DROP_PY = ["test", "tests", "idlelib", "turtledemo", "ensurepip", "pydoc_data"]

KEEP_LOCALES = ("C.UTF-8", "C", "POSIX", "zh_CN", "en", "en_US")


def rm(path, dry, log):
    if not os.path.exists(path) and not os.path.islink(path):
        return 0
    size = 0
    if os.path.isdir(path) and not os.path.islink(path):
        for d, _dd, fs in os.walk(path):
            for f in fs:
                p = os.path.join(d, f)
                try:
                    size += os.path.getsize(p)
                except OSError:
                    pass
    else:
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
    if not dry:
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path, ignore_errors=True)
        else:
            try:
                os.unlink(path)
            except OSError:
                pass
    log.append((path, size))
    return size


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("rootfs")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if not os.path.isdir(a.rootfs):
        print("[FAIL] rootfs 目录不存在: " + a.rootfs)
        return 1

    log = []
    total = 0

    for rel in DROP_DIRS:
        total += rm(os.path.join(a.rootfs, rel), a.dry_run, log)

    # /usr/share/doc：只删非 copyright 的文件
    docroot = os.path.join(a.rootfs, "usr/share/doc")
    if os.path.isdir(docroot):
        for pkg in os.listdir(docroot):
            pdir = os.path.join(docroot, pkg)
            if not os.path.isdir(pdir) or os.path.islink(pdir):
                continue
            for f in os.listdir(pdir):
                if f == "copyright":
                    continue
                total += rm(os.path.join(pdir, f), a.dry_run, log)

    # perl 的 POD 文档
    for base in ("usr/share/perl", "usr/share/perl5"):
        p = os.path.join(a.rootfs, base)
        if not os.path.isdir(p):
            continue
        for d, _dd, fs in os.walk(p):
            if os.path.basename(d) in ("pod", "pods"):
                total += rm(d, a.dry_run, log)

    # python 的测试/示例/缓存
    for base in ("usr/local/lib", "usr/lib"):
        root = os.path.join(a.rootfs, base)
        if not os.path.isdir(root):
            continue
        for name in os.listdir(root):
            if not name.startswith("python"):
                continue
            lib = os.path.join(root, name)
            for sub in DROP_PY:
                total += rm(os.path.join(lib, sub), a.dry_run, log)
            for d, dirs, _fs in os.walk(lib):
                for dd in list(dirs):
                    if dd == "__pycache__":
                        total += rm(os.path.join(d, dd), a.dry_run, log)
                        dirs.remove(dd)

    # locale：保留 C/C.UTF-8/中文/英文
    loc = os.path.join(a.rootfs, "usr/share/locale")
    if os.path.isdir(loc):
        for name in os.listdir(loc):
            if name in KEEP_LOCALES:
                continue
            total += rm(os.path.join(loc, name), a.dry_run, log)

    for path, size in log[:12]:
        print("  删 %-52s %6.1f MB" % (os.path.relpath(path, a.rootfs), size / 1e6))
    if len(log) > 12:
        print("  ...（另有 %d 项）" % (len(log) - 12))
    print("[ok]   瘦身%s：%d 项，共 %.1f MB"
          % ("（dry-run）" if a.dry_run else "", len(log), total / 1e6))
    return 0


if __name__ == "__main__":
    sys.exit(main())
