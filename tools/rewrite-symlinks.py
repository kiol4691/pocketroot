#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
rootfs 内部符号链接改写（构建期）
================================

问题
----
Alpine 等发行版的 rootfs 里有 300+ 个**绝对**符号链接：

    /bin/ash      -> /bin/busybox
    /sbin/apk     -> /bin/busybox
    /usr/lib/...  -> /lib/...

符号链接由**内核**解析，不经过我们的 LD_PRELOAD 钩子。当 rootfs 不在文件
系统根部时（/data/data/com.pocketroot/files/rootfs），这些链接会被解析到
宿主的 /bin/busybox —— 不存在，于是：

    ld-musl-aarch64.so.1: cannot load .../bin/ash: No such file or directory

（这正是 zroot-lab 0.1.1 定位到的故障，当时 306 个链接全部失效。）

方案差异
--------
zroot-lab 的做法：解包时把绝对链接改写成**绝对真实路径**（$dest + target）。
  可用，但 rootfs 位置被固化 —— 一旦移动目录（如迁移到 SD 卡、备份恢复），
  所有链接失效。

本脚本的做法：改写成**相对链接**（os.path.relpath）。
  位置无关：rootfs 整体搬到任何地方、任何层级都能解析。
  例：
    /bin/ash        -> /bin/busybox     ==>  ash -> busybox
    /usr/lib/a.so   -> /lib/a.so.1      ==>  a.so -> ../../lib/a.so.1

  只有指向 rootfs **外部**的链接（/proc、/sys、/dev 等）保持原样 ——
  它们本来就应当穿透到宿主。

用法
----
    python3 tools/rewrite-symlinks.py ROOTFS [--check]

    --check   只统计不修改

退出码
------
    0  成功
    1  rootfs 不存在
"""

import os
import sys

# 指向这些前缀的链接**不改写**（它们是宿主挂载点，应当穿透）
PASSTHROUGH = ("/proc", "/sys", "/dev", "/system", "/apex", "/vendor", "/data", "/tmp")


def should_rewrite(target: str) -> bool:
    """仅改写指向 rootfs 内部的绝对链接。"""
    if not target.startswith("/"):
        return False                       # 已是相对链接
    for p in PASSTHROUGH:
        if target == p or target.startswith(p + "/"):
            return False
    return True


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = [a for a in sys.argv[1:] if a.startswith("--")]
    check_only = "--check" in flags

    if not args:
        print(__doc__)
        return 1

    rootfs = os.path.abspath(args[0])
    if not os.path.isdir(rootfs):
        print(f"[FAIL] rootfs 目录不存在: {rootfs}")
        return 1

    total = rewritten = skipped = failed = 0
    examples = []

    for dirpath, dirnames, filenames in os.walk(rootfs):
        for name in list(dirnames) + list(filenames):
            path = os.path.join(dirpath, name)
            if not os.path.islink(path):
                continue

            total += 1
            target = os.readlink(path)

            if not should_rewrite(target):
                skipped += 1
                continue

            # 目标在 rootfs 内的真实路径
            abs_target = os.path.normpath(
                os.path.join(rootfs, target.lstrip("/")))
            rel = os.path.relpath(abs_target, os.path.dirname(path))

            if len(examples) < 5:
                rel_path = os.path.relpath(path, rootfs)
                examples.append(f"  {rel_path}: {target} -> {rel}")

            if not check_only:
                try:
                    os.unlink(path)
                    os.symlink(rel, path)
                    rewritten += 1
                except OSError as e:
                    failed += 1
                    print(f"[warn] 改写失败 {path}: {e}")
            else:
                rewritten += 1

    print(f"符号链接总计: {total}")
    print(f"  改写为相对: {rewritten}")
    print(f"  保持原样  : {skipped}（相对链接 / 指向宿主挂载点）")
    if failed:
        print(f"  失败      : {failed}")
    if examples:
        print("示例:")
        for e in examples:
            print(e)

    if failed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
