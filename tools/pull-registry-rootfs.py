#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
从 OCI 镜像仓库拉取 arm64 rootfs（Docker Hub / GHCR 均可）。

为什么需要
----------
仓库不内置 glibc rootfs 镜像（体积与再分发条款），构建时按需拉取。
没有 docker 二进制也能做：OCI registry 就是 HTTP + 匿名 token。

用法
----
    # Docker Hub 官方镜像
    python3 tools/pull-registry-rootfs.py docker.io/library/debian:trixie-slim -o assets/glibc-rootfs.tar.gz

    # GHCR
    python3 tools/pull-registry-rootfs.py ghcr.io/bell-sw/alpaquita-linux-base:stream-glibc \\
        -o assets/glibc-rootfs.tar.gz

    # 只打印可用于钉住版本的 digest，不下载
    python3 tools/pull-registry-rootfs.py docker.io/library/debian:trixie-slim --print-digests

退出码
------
    0  成功
    1  平台上没有该架构 / 下载失败
    2  参数错误
"""

import argparse
import hashlib
import json
import sys
import urllib.request

ACCEPTS = ",".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.layer.v1.tar+gzip",
])

# registry -> (api base, token endpoint)
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
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def token_for(reg, repo):
    url = REGISTRIES[reg][1].format(repo=repo)
    return json.loads(http(url, accept="application/json"))["token"]


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

    body = http("%s/%s/manifests/%s" % (base, repo, tag), auth)
    m = json.loads(body)

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
        body = http("%s/%s/manifests/%s" % (base, repo, digest), auth)
        m = json.loads(body)

    layers = m.get("layers", [])
    if not layers:
        print("manifest 里没有 layer")
        return 1

    print("image: %s:%s (%s)" % (repo, tag, a.arch))
    for l in layers:
        print("  layer %s  %d bytes" % (l["digest"], l["size"]))
    if a.print_digests:
        print("钉版本用：%s@%s" % (repo, m.get("config", {}).get("digest", "?")))
        return 0

    h = hashlib.sha256()
    with open(a.out, "wb") as fh:
        for l in layers:
            data = http("%s/%s/blobs/%s" % (base, repo, l["digest"]), auth)
            fh.write(data)
            h.update(data)
    print("写出 %s (%d bytes)" % (a.out, h.hexdigest()[:16]))
    print("sha256: " + h.hexdigest())
    print("下一步: ROOTFS_TGZ=%s ./build.sh --glibc" % a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
