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
    python3 tools/add-debs.py ROOTFS [--pkgs libgomp1,libatomic1,curl] \
            [--suite trixie] [--manifest out.json]

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
DEFAULT_PKGS = [
    "libgomp1",        # OpenMP：PyTorch CPU 后端必需
    "libatomic1",      # 同上，部分数学库用到
    "procps",          # ps / top
    "curl",
    "ca-certificates",
    "less",
    "file",
    "tzdata",
]


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
        if name:
            out.append(name)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("rootfs")
    ap.add_argument("--pkgs", default=",".join(DEFAULT_PKGS))
    ap.add_argument("--suite", default="trixie")
    ap.add_argument("--manifest", default="")
    a = ap.parse_args()

    if not os.path.isdir(a.rootfs):
        print("[FAIL] rootfs 目录不存在: " + a.rootfs)
        return 2

    print("读取 %s 的包索引..." % a.suite)
    index, provides = load_index(a.suite)
    print("  %d 个包" % len(index))

    have = installed_names(a.rootfs)
    queue = [p.strip() for p in a.pkgs.split(",") if p.strip()]
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
    with open(info_path, "w", encoding="utf-8") as fh:
        json.dump({"suite": a.suite, "mirror": MIRROR, "added": added},
                  fh, indent=2, ensure_ascii=False)
    print("[ok]   补装 %d 个包，清单写入 /etc/pocketroot-debs.json" % len(added))

    if a.manifest:
        with open(a.manifest, "w", encoding="utf-8") as fh:
            json.dump({"suite": a.suite, "added": added}, fh, indent=2, ensure_ascii=False)
        print("[ok]   清单已写出: " + a.manifest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
