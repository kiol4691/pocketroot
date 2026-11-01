#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
从 GHCR 拉取 Alpaquita Linux (glibc) 的 arm64 镜像层，合成为 rootfs。

为什么需要：hub.docker.com 在本机网络不可达，而 ghcr.io 可达。
Alpaquita 官方在 GHCR 托管了 bell-sw/alpaquita-linux-base，
其中 stream-glibc 标签即为 glibc 变体（对应官网的 "MiniRoot with GLIBC"）。

用法:
    python3 ghcr-pull.py [tag] [outdir]
"""
import io
import json
import os
import shutil
import sys
import tarfile
import urllib.request

REPO = "bell-sw/alpaquita-linux-base"
REG = "https://ghcr.io"


def get_token():
    scope = "repository:" + REPO + ":pull"
    url = "%s/token?scope=%s&service=ghcr.io" % (REG, urllib.parse.quote(scope))
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.load(r)["token"]


def fetch(tok, path, accepts):
    req = urllib.request.Request(REG + path)
    req.add_header("Authorization", "Bearer " + tok)
    req.add_header("Accept", ", ".join(accepts))
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read(), r.headers.get("Content-Type", "")


MANI_ACCEPTS = [
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
]


def pick_arm64(tok, tag):
    raw, _ = fetch(tok, "/v2/%s/manifests/%s" % (REPO, tag), MANI_ACCEPTS)
    d = json.loads(raw)

    if "manifests" in d:                      # index / manifest list
        for m in d["manifests"]:
            plat = m.get("platform", {})
            if plat.get("architecture") in ("arm64", "aarch64"):
                dig = m["digest"]
                raw2, _ = fetch(tok, "/v2/%s/manifests/%s" % (REPO, dig), MANI_ACCEPTS)
                return json.loads(raw2)
        raise SystemExit("镜像列表中未找到 arm64 条目，可用: %s" %
                         [(m.get("platform") or {}).get("architecture") for m in d["manifests"]])
    return d


def extract_layer(tok, digest, outdir):
    raw, _ = fetch(tok, "/v2/%s/blobs/%s" % (REPO, digest),
                   ["application/vnd.oci.image.layer.v1.tar+gzip",
                    "application/vnd.docker.image.rootfs.diff.tar.gzip"])
    tf = tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz")

    removed = []
    for m in tf.getmembers():
        name = m.name
        # 去掉 "./" 前缀；跳过绝对/逃逸路径
        while name.startswith("./"):
            name = name[1:]
        if name.startswith("/") or ".." in name.split("/"):
            continue
        base = os.path.basename(name)
        if base.startswith(".wh."):           # OCI whiteout
            target = os.path.join(outdir, os.path.dirname(name), base[4:])
            removed.append(target)
            continue
        try:
            tf.extract(m, outdir, numeric_owner=False)
        except Exception as e:
            print("   [warn] 解压失败 %s: %s" % (name, e))

    for p in removed:
        try:
            if os.path.isdir(p) and not os.path.islink(p):
                shutil.rmtree(p)
            elif os.path.exists(p) or os.path.islink(p):
                os.remove(p)
        except Exception:
            pass


def main():
    tag = sys.argv[1] if len(sys.argv) > 1 else "stream-glibc"
    outdir = sys.argv[2] if len(sys.argv) > 2 else "/tmp/alpaquita-rootfs"

    print("获取 token ...")
    tok = get_token()
    print("拉取 manifest:", tag)
    man = pick_arm64(tok, tag)

    layers = man.get("layers", [])
    print("层数:", len(layers))

    os.makedirs(outdir, exist_ok=True)
    for i, L in enumerate(layers):
        size = L.get("size", 0)
        print("  layer %d/%d  %.1f MB" % (i + 1, len(layers), size / 1048576.0))
        extract_layer(tok, L["digest"], outdir)

    print("完成 ->", outdir)
    # 简易统计
    n = sum(len(f) for _, _, f in os.walk(outdir))
    print("文件数:", n)
    print("顶层:", sorted(os.listdir(outdir))[:20])


if __name__ == "__main__":
    main()
