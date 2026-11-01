#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
给 rootfs 离线装 Python 包（解 wheel 进 site-packages）
======================================================

为什么需要
----------
宿主机 x86_64、目标 rootfs aarch64、没有 qemu —— 没法在 rootfs 里跑 pip。
但 wheel 本质是个 zip：把内容放进 site-packages 就是"安装"了，不需要执行任何
目标架构的代码。所以做法是：在宿主机下载对应 ABI 的 wheel → 解压进 rootfs。

关键点
------
- **ABI 必须匹配**：cp312 的 wheel 放进 Python 3.13 会 ImportError。
  因此按 `cp313 + aarch64` 挑选，纯 Python 包则取 `none-any`；
- 解压后做一次**架构自检**：凡 `.so` 都读 ELF 头确认是 aarch64，
  混进别的架构会当场报错而不是等到设备上才炸；
- wheel 里的 `*.data/scripts/*` 放进 `/usr/local/bin`。

已知局限
--------
- 不校验 RECORD 的哈希（那是 pip 的活）；
- 依赖解析只看 `Requires-Dist`，且跳过带 `extra ==` 的可选依赖；
- `pip uninstall` 可用（dist-info 是完整的），但 pip 认为它们由 pip 安装。

用法
----
    python3 tools/add-wheels.py ROOTFS [--pkgs numpy,pandas,scipy] \
            [--py 3.13] [--arch aarch64] [--manifest out.json]

退出码
------
    0  成功
    1  下载/解压失败或架构不符
    2  参数错误
"""

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

DEFAULT_PKGS = [
    "numpy", "pandas", "scipy", "matplotlib",
    "scikit-learn", "pillow", "requests",
]

# ELF 头：e_machine = 183 是 AArch64
AARCH64_MACHINE = 183


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "pocketroot"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return r.read()


def project(name):
    return json.loads(get("https://pypi.org/pypi/%s/json" % name))


def pick_wheel(files, py_tag: str, arch_key: str):
    cands = [f for f in files if f["packagetype"] == "bdist_wheel"]
    # 1) 纯 Python
    for f in cands:
        if "none-any" in f["filename"]:
            return f
    # 2) 精确 ABI + 架构
    for f in cands:
        if py_tag in f["filename"] and arch_key in f["filename"]:
            return f
    # 3) abi3 + 架构
    for f in cands:
        if "abi3" in f["filename"] and arch_key in f["filename"]:
            return f
    return None


def deps_of(path):
    with zipfile.ZipFile(path) as z:
        metas = [n for n in z.namelist() if n.endswith("METADATA")]
        if not metas:
            return []
        text = z.read(metas[0]).decode("utf-8", "replace")
    out = []
    for line in text.splitlines():
        if not line.startswith("Requires-Dist:"):
            continue
        item = line.split(":", 1)[1].strip()
        if "extra ==" in item:
            continue
        name = re.split(r"[ ;<>=!~\[(]", item, 1)[0].strip().lower()
        if name:
            out.append(name)
    return out


def check_so_arch(root: str) -> list:
    """解压出来的 .so 必须是目标架构。"""
    bad = []
    for dirpath, _d, files in os.walk(root):
        for f in files:
            if not (f.endswith(".so") or ".so." in f):
                continue
            p = os.path.join(dirpath, f)
            try:
                with open(p, "rb") as fh:
                    head = fh.read(20)
            except OSError:
                continue
            if len(head) < 20 or head[:4] != b"\x7fELF":
                continue
            machine = int.from_bytes(head[18:20], "little")
            if machine != AARCH64_MACHINE:
                bad.append(os.path.relpath(p, root) + " (machine=%d)" % machine)
    return bad


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("rootfs")
    ap.add_argument("--pkgs", default=",".join(DEFAULT_PKGS))
    ap.add_argument("--py", default="3.13")
    ap.add_argument("--arch", default="aarch64")
    ap.add_argument("--site", default="")
    ap.add_argument("--manifest", default="")
    ap.add_argument("--strip-only", action="store_true",
                    help="只做瘦身，不下载新包（配合 --strip）")
    ap.add_argument("--strip", default="",
                    help="用 zig objcopy --strip-debug 瘦身 .so（传 zig 路径）")
    a = ap.parse_args()

    if not os.path.isdir(a.rootfs):
        print("[FAIL] rootfs 目录不存在: " + a.rootfs)
        return 2

    py_tag = "cp" + a.py.replace(".", "")          # 3.13 -> cp313
    site = a.site
    if not site:
        cand = os.path.join(a.rootfs, "usr/local/lib/python%s/site-packages" % a.py)
        if os.path.isdir(cand):
            site = cand
        else:
            print("[FAIL] 找不到 site-packages，请用 --site 指定")
            return 2
    print("site-packages: " + site)

    queue = [] if a.strip_only else [p.strip() for p in a.pkgs.split(",") if p.strip()]
    seen, order = set(), []
    tmp = tempfile.mkdtemp(prefix="add-wheels-")
    added = []
    try:
        while queue:
            name = queue.pop(0)
            if name in seen:
                continue
            seen.add(name)
            try:
                proj = project(name)
            except Exception as e:
                print("  !! 查询 %s 失败: %s" % (name, e))
                continue
            ver = proj["info"]["version"]
            f = pick_wheel(proj["releases"].get(ver, []) or proj["urls"], py_tag, a.arch)
            if not f:
                print("  !! %s 没有 %s/%s 的 wheel，跳过" % (name, py_tag, a.arch))
                continue
            path = os.path.join(tmp, f["filename"])
            data = get(f["url"])
            with open(path, "wb") as fh:
                fh.write(data)
            order.append(name)
            added.append({"package": name, "version": ver,
                          "wheel": f["filename"],
                          "sha256": hashlib.sha256(data).hexdigest(),
                          "size": len(data)})
            print("  %-16s %-10s %7.1f MB  %s" % (name, ver, len(data) / 1e6,
                                                  f["filename"][:48]))
            for d in deps_of(path):
                if d not in seen:
                    queue.append(d)
    finally:
        pass

    # 解压（按依赖顺序）
    for name in order:
        item = next(x for x in added if x["package"] == name)
        path = os.path.join(tmp, item["wheel"])
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                if n.startswith("..") or os.path.isabs(n):
                    continue
                if n.endswith("/"):
                    continue
                # wheel 里的 <name>.data/ 只保留 scripts/，其余（headers、
                # purelib 副本）不解到 site-packages，否则会留下垃圾目录。
                top = n.split("/")[0]
                if top.endswith(".data"):
                    if "/scripts/" in n:
                        target = os.path.join(a.rootfs, "usr/local/bin",
                                              os.path.basename(n))
                        os.makedirs(os.path.dirname(target), exist_ok=True)
                        with z.open(n) as src, open(target, "wb") as dst:
                            shutil.copyfileobj(src, dst)
                        continue
                    continue
                # 脚本类数据放到 /usr/local/bin
                if n.startswith("scripts/") and "/data/" in n:
                    continue
                target = os.path.join(site, n)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with z.open(n) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)

    if a.strip:
        before = sum(os.path.getsize(os.path.join(d, fn))
                     for d, _dd, fs in os.walk(site) for fn in fs)
        n_stripped = 0
        for dirpath, _d, files in os.walk(site):
            for fn in files:
                if not (fn.endswith(".so") or ".so." in fn):
                    continue
                p = os.path.join(dirpath, fn)
                tmp_out = p + ".stripped"
                rc = subprocess.call([a.strip, "objcopy", "--strip-debug", p, tmp_out])
                if rc == 0 and os.path.exists(tmp_out):
                    os.replace(tmp_out, p)
                    n_stripped += 1
                elif os.path.exists(tmp_out):
                    os.unlink(tmp_out)
        after = sum(os.path.getsize(os.path.join(d, fn))
                    for d, _dd, fs in os.walk(site) for fn in fs)
        print("[ok]   瘦身 %d 个 .so：%d MB -> %d MB（-%.0f%%）"
              % (n_stripped, before // (1 << 20), after // (1 << 20),
                 100.0 * (before - after) / max(before, 1)))

    bad = check_so_arch(site)
    if bad:
        print("[FAIL] 有非 %s 的 .so：" % a.arch)
        for b in bad[:10]:
            print("         " + b)
        return 1
    print("[ok]   架构自检通过（.so 全为 %s）" % a.arch)

    shutil.rmtree(tmp, ignore_errors=True)

    if added:
        info = os.path.join(a.rootfs, "etc/pocketroot-wheels.json")
        with open(info, "w", encoding="utf-8") as fh:
            json.dump({"python": a.py, "arch": a.arch, "site": site,
                       "packages": added}, fh, indent=2, ensure_ascii=False)
        print("[ok]   安装 %d 个包，清单写入 /etc/pocketroot-wheels.json" % len(added))
    if a.manifest and added:
        with open(a.manifest, "w", encoding="utf-8") as fh:
            json.dump({"python": a.py, "packages": added}, fh, indent=2, ensure_ascii=False)
        print("[ok]   清单已写出: " + a.manifest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
