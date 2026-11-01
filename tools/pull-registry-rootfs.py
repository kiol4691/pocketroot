#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
从 OCI 镜像仓库拉取 arm64 rootfs（Docker Hub / GHCR 均可）。

为什么需要
----------
仓库不内置 glibc rootfs 镜像（体积与再分发条款），构建时按需拉取。
没有 docker 二进制也能做：OCI registry 就是 HTTP + 匿名 token。

做法
----
逐层下载并在**内存里解压叠加**，处理 OCI 的 whiteout 标记，最后重新打包成一个
tar.gz。为什么不直接把各层的 gzip 拼起来：GNU tar 读到第一个归档的 EOF 块就停，
后面的层会被静默丢弃（实测：python:3.13-slim 拼起来只解出 Debian 基础层，
105 MB 里根本没有 /usr/local/bin/python）。

用法
----
    python3 tools/pull-registry-rootfs.py docker.io/library/debian:trixie-slim \
            -o /tmp/debian-trixie-slim-arm64.tar.gz
    python3 tools/pull-registry-rootfs.py ghcr.io/bell-sw/alpaquita-linux-base:stream-glibc \
            -o /tmp/alpaquita.tar.gz
    python3 tools/pull-registry-rootfs.py docker.io/library/python:3.13-slim --print-digests

退出码
------
    0  成功
    1  平台上没有该架构 / 下载失败
    2  参数错误
"""

import argparse
import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
import urllib.request

ACCEPTS = ",".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.layer.v1.tar+gzip",
])

REGISTRIES = {
    "docker.io": ("https://registry-1.docker.io/v2",
                  "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"),
    "ghcr.io":   ("https://ghcr.io/v2",
                  "https://ghcr.io/token?service=ghcr.io&scope=repository:{repo}:pull"),
}


def http(url, headers=None, accept=ACCEPTS):
    h = dict(headers or {})
    if accept:
        h["Accept"] = accept
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=180) as r:
        return r.read()


def token_for(reg, repo):
    return json.loads(http(REGISTRIES[reg][1].format(repo=repo),
                           accept="application/json"))["token"]


def apply_whiteouts(root):
    """OCI whiteout：`.wh.<name>` 表示删除下层同名路径，
    `.wh..opq` 表示清空该目录下层内容。"""
    for dirpath, dirnames, filenames in os.walk(root):
        for f in filenames:
            if f == ".wh..opq":
                for e in os.listdir(dirpath):
                    if e == f:
                        continue
                    p = os.path.join(dirpath, e)
                    shutil.rmtree(p) if os.path.isdir(p) and not os.path.islink(p) else os.unlink(p)
                os.unlink(os.path.join(dirpath, f))
            elif f.startswith(".wh."):
                target = os.path.join(dirpath, f[len(".wh."):])
                if os.path.isdir(target) and not os.path.islink(target):
                    shutil.rmtree(target, ignore_errors=True)
                elif os.path.exists(target) or os.path.islink(target):
                    os.unlink(target)
                os.unlink(os.path.join(dirpath, f))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("image", help="docker.io/library/debian:trixie-slim")
    ap.add_argument("-o", "--out", default="rootfs.tar.gz")
    ap.add_argument("--arch", default="arm64")
    ap.add_argument("--print-digests", action="store_true")
    a = ap.parse_args()

    ref = a.image
    if ":" in ref:
        ref, tag = ref.rsplit(":", 1)
    else:
        tag = "latest"
    if ref.startswith("docker.io/"):
        reg, repo = "docker.io", ref[len("docker.io/"):]
    elif ref.startswith("ghcr.io/"):
        reg, repo = "ghcr.io", ref[len("ghcr.io/"):]
    elif "/" not in ref:
        reg, repo = "docker.io", "library/" + ref
    else:
        print("未知仓库：" + ref)
        return 2

    base = REGISTRIES[reg][0]
    auth = {"Authorization": "Bearer " + token_for(reg, repo)}

    m = json.loads(http("%s/%s/manifests/%s" % (base, repo, tag), auth))
    if "manifests" in m:
        digest = None
        for e in m["manifests"]:
            p = e.get("platform", {})
            if p.get("architecture") == a.arch and p.get("os") == "linux":
                digest = e["digest"]
                break
        if digest is None:
            print("该镜像没有 linux/%s 的变体" % a.arch)
            return 1
        m = json.loads(http("%s/%s/manifests/%s" % (base, repo, digest), auth))

    layers = m.get("layers", [])
    if not layers:
        print("manifest 里没有 layer")
        return 1

    print("image: %s:%s (%s)" % (repo, tag, a.arch))
    for l in layers:
        print("  layer %s  %d bytes" % (l["digest"][:19], l["size"]))
    if a.print_digests:
        print("钉版本用: %s@%s" % (repo, m.get("config", {}).get("digest", "?")))
        return 0

    tmp = tempfile.mkdtemp(prefix="pull-rootfs-")
    try:
        for l in layers:
            data = http("%s/%s/blobs/%s" % (base, repo, l["digest"]), auth)
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
                tf.extractall(tmp)
        apply_whiteouts(tmp)
        n = sum(len(f) for _r, _d, f in os.walk(tmp))
        print("解出 %d 个条目" % n)
        with tarfile.open(a.out, "w:gz") as tf:
            tf.add(tmp, arcname=".")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    h = hashlib.sha256()
    with open(a.out, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    print("写出 %s（%d bytes）" % (a.out, os.path.getsize(a.out)))
    print("sha256: " + h.hexdigest())
    print("下一步: ROOTFS_TGZ=%s ./build.sh --glibc" % a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
