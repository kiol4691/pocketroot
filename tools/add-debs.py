#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
给 rootfs 补装 arm64 的 .deb（高频使用库 / 工具）
================================================

为什么需要
----------
Debian 的 slim 镜像刻意裁掉了非必需组件，其中一些是本项目会用到的：

- `libgomp1`：OpenMP 运行时。PyTorch 的 CPU 后端要用，缺了 torch 直接加载失败；
- `libatomic1`：同上，部分数学库会用；
- `procps`（ps / top）、`curl`、`ca-certificates`、`less`、`file`、`tzdata`：
  在 rootfs 里做开发时几乎必然要用到。

为什么不在设备里 `apt-get install`
----------------------------------
宿主机是 x86_64，目标 rootfs 是 arm64，没有 qemu 可以跑 apt。
但安装 deb 并不需要执行任何 arm64 代码 —— `dpkg-deb -x` 只是解包，
因此可以在宿主机上完成：下载 deb → 解析依赖 → 逐个解包进 rootfs。

已知局限
--------
- 不写 `/var/lib/dpkg/status`，因此 `dpkg -l` 看不到这些包（功能正常，
  但后续 `apt-get` 可能重复安装它们）。补齐需要模拟 dpkg 的状态数据库，暂不做；
- 依赖解析只取 `Depends` 里每个条目的第一个选项，且版本约束按"已安装即满足"处理。

用法
----
    python3 tools/add-debs.py ROOTFS [--profile minimal|light|full] \
            [--pkgs 追加的包] [--suite trixie] [--dry-run] [--manifest out.json]
    python3 tools/add-debs.py --list-profiles

装了哪些 profile 写在文件里的 PROFILES 表，--list-profiles 直接打印。


退出码
------
    0  成功
    1  下载或解包失败
    2  参数错误
"""

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request

MIRROR = "http://deb.debian.org/debian"

# 三档预设。默认 light —— 轻度编码 + 日常办公够用；
# 想加包用 --pkgs 追加，不必改这里。
PROFILES = {
    # 只保证"Python 的二进制轮子能加载"：
    # libgomp 是 OpenMP（numpy/torch 的 CPU 后端），libatomic 是部分数学库
    "minimal": [
        "libgomp1",
        "libatomic1",
        "ca-certificates",
        "tzdata",
    ],
    # 轻度编码 + 日常办公：命令行工具齐了，但没有编译器
    "light": [
        "libgomp1",
        "libatomic1",
        "ca-certificates",
        "tzdata",
        "git",
        "openssh-client",
        "vim-tiny",
        "nano",
        "less",
        "file",
        "procps",
        "curl",
        "zip",
        "unzip",
        "jq",
        "make",
    ],
    # 在 rootfs 里能自己编译东西（gcc 全家桶，体积 +150 MB 量级）
    "full": [
        "build-essential",
        "rsync",
        "tmux",
        "tree",
        "sqlite3",
        "htop",
        "patch",
        "gdb",
        "strace",
    ],
}

# full 是在 light 之上叠的，而不是替换 —— 否则装完 full 反而没有 git
PROFILES["full"] = PROFILES["light"] + PROFILES["full"]
DEFAULT_PROFILE = "light"


def get(url, binary=True):
    req = urllib.request.Request(url, headers={"User-Agent": "pocketroot"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return r.read()


def load_index(suite: str, comp: str = "main", arch: str = "arm64"):
    url = "%s/dists/%s/%s/binary-%s/Packages.gz" % (MIRROR, suite, comp, arch)
    raw = get(url)
    text = gzip.GzipFile(fileobj=io.BytesIO(raw)).read().decode("utf-8", "replace")
    pkgs = {}
    provides = {}
    for block in text.split("\n\n"):
        if not block.strip():
            continue
        fields = {}
        for line in block.splitlines():
            if line.startswith(" ") or not line:
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                fields[k.strip()] = v.strip()
        name = fields.get("Package")
        if not name:
            continue
        pkgs[name] = fields
        for p in fields.get("Provides", "").split(","):
            provides[p.strip().split("(")[0].strip()] = name
    return pkgs, provides


def installed_names(rootfs: str) -> set:
    """读 rootfs 里的 dpkg 状态库，已装的包不再重复解包。"""
    names = set()
    st = os.path.join(rootfs, "var/lib/dpkg/status")
    if os.path.exists(st):
        for line in open(st, encoding="utf-8", errors="replace"):
            if line.startswith("Package: "):
                names.add(line.split(":", 1)[1].strip())
    # 本工具装过的包（不写 dpkg 状态库，所以单独记一份清单）
    man = os.path.join(rootfs, "etc/pocketroot-debs.json")
    if os.path.exists(man):
        try:
            data = json.load(open(man, encoding="utf-8"))
            for item in data.get("added", []):
                names.add(item.get("package", ""))
        except (ValueError, OSError):
            pass
    return names


def dep_names(dep_field: str):
    """:"libc6 (>= 2.38), libgcc-s1" -> ["libc6", "libgcc-s1"]（只取第一选项）"""
    out = []
    for item in dep_field.split(","):
        item = item.strip()
        if not item:
            continue
        first = item.split("|")[0].strip()
        name = re.split(r"[ (<>=]", first, 1)[0].strip()
        # 去掉架构限定（perl:any、python3:any），索引里没有带后缀的条目
        name = name.split(":")[0]
        if name:
            out.append(name)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("rootfs", nargs="?", default="")
    ap.add_argument("--profile", default=DEFAULT_PROFILE,
                    choices=sorted(PROFILES),
                    help="预设包集合（默认 light）")
    ap.add_argument("--pkgs", default="", help="追加的包，逗号分隔")
    ap.add_argument("--list-profiles", action="store_true")
    ap.add_argument("--dry-run", action="store_true",
                    help="只解析依赖并打印，不下载")
    ap.add_argument("--suite", default="trixie")
    ap.add_argument("--manifest", default="")
    a = ap.parse_args()

    if a.list_profiles:
        for name in sorted(PROFILES):
            print("%-8s %s" % (name, " ".join(PROFILES[name])))
        return 0

    if not os.path.isdir(a.rootfs):
        print("[FAIL] rootfs 目录不存在: " + a.rootfs)
        return 2

    print("读取 %s 的包索引..." % a.suite)
    index, provides = load_index(a.suite)
    print("  %d 个包" % len(index))

    have = installed_names(a.rootfs)
    wanted = list(PROFILES[a.profile])
    wanted += [p.strip() for p in a.pkgs.split(",") if p.strip()]
    print("profile=%s，请求 %d 个包" % (a.profile, len(wanted)))
    queue = wanted
    chosen = []
    seen = set()
    missing = []
    while queue:
        name = queue.pop(0)
        if name in seen:
            continue
        seen.add(name)
        if name in have:
            continue
        real = name if name in index else provides.get(name)
        if not real or real not in index:
            missing.append(name)
            continue
        if real in seen and real != name:
            continue
        fields = index[real]
        seen.add(real)
        chosen.append(real)
        for d in dep_names(fields.get("Depends", "")):
            if d not in seen:
                queue.append(d)

    if missing:
        print("  !! 索引里找不到：%s" % ", ".join(missing))
    print("待装 %d 个包：%s" % (len(chosen), " ".join(chosen)))
    if a.dry_run:
        print("[ok]   dry-run：未下载")
        return 0

    tmp = tempfile.mkdtemp(prefix="add-debs-")
    added = []
    try:
        for name in chosen:
            fields = index[name]
            fn = fields["Filename"]
            url = "%s/%s" % (MIRROR, fn)
            deb = os.path.join(tmp, name + ".deb")
            try:
                data = get(url)
            except Exception as e:
                print("[FAIL] 下载 %s 失败: %s" % (name, e))
                return 1
            with open(deb, "wb") as fh:
                fh.write(data)
            rc = subprocess.call(["dpkg-deb", "-x", deb, a.rootfs])
            if rc != 0:
                print("[FAIL] 解包 %s 失败" % name)
                return 1
            added.append({
                "package": name,
                "version": fields.get("Version", ""),
                "filename": fn,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            })
            print("  %-18s %-16s %6.1f MB" % (name, fields.get("Version", ""), len(data) / 1e6))
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)

    info_path = os.path.join(a.rootfs, "etc/pocketroot-debs.json")
    prev = []
    if os.path.exists(info_path):
        try:
            prev = json.load(open(info_path, encoding="utf-8")).get("added", [])
        except (ValueError, OSError):
            prev = []
    merged = {x["package"]: x for x in prev}
    for x in added:
        merged[x["package"]] = x
    with open(info_path, "w", encoding="utf-8") as fh:
        json.dump({"suite": a.suite, "mirror": MIRROR,
                   "added": list(merged.values())},
                  fh, indent=2, ensure_ascii=False)
    print("[ok]   补装 %d 个包，清单写入 /etc/pocketroot-debs.json" % len(added))

    if a.manifest:
        with open(a.manifest, "w", encoding="utf-8") as fh:
            json.dump({"suite": a.suite, "added": added}, fh, indent=2, ensure_ascii=False)
        print("[ok]   清单已写出: " + a.manifest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
