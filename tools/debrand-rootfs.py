#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
构建期去品牌化（glibc 变体）
============================

为什么需要
----------
分发的 glibc rootfs 是**修改版**（打了 seccomp 补丁，见 patch-glibc-syscalls.py）。
以发行版原名分发修改版，容易被理解为"该发行版的官方产物"或获得其背书 ——
Ubuntu 是 Canonical Ltd. 的注册商标，Alpaquita 是 BellSoft 的商标，
本项目与二者均无关联，也未获其授权。

所以构建时把**标识性内容**换成本项目的名字（pocketroot base），并删掉 logo 与
motd 广告脚本。同时有一条硬约束：

    功能性内容一律保留。

包数据库、apt 源、keyring、/usr/share/doc 下的版权与许可声明都不动 ——
改名不能让 apt/dpkg 装不了包，也不能把别人的版权声明"去品牌化"掉。
因此 dpkg -l 里仍会看到 ubuntu-keyring 之类的包名：那是**指名性使用**
（nominative use），是功能与合规所必需，不属于本项目主张的品牌。

改什么
------
  改写：/etc/os-release（真实文件在 /usr/lib/os-release，/etc 下是符号链接）
        /etc/issue、/etc/issue.net、/etc/motd、/etc/lsb-release
        /etc/dpkg/origins/default（指向新建的 pocketroot）
  删除：/etc/<发行版>-release（纯标识文件）
        /etc/update-motd.d/*（欢迎语与广告；其中 50-motd-news 还会联网抓取）
        /usr/share/{pixmaps,backgrounds,icons,plymouth} 下的发行版 logo
  保留：/etc/apt/**（含 sources.list、trusted.gpg.d）、/usr/share/doc/**、包数据库

用法
----
    python3 tools/debrand-rootfs.py ROOTFS [--check] [--manifest out.json]

退出码
------
    0  成功（或 --check 未发现残留）
    1  --check 发现残留 / 目标缺失
    2  参数错误
"""

import glob
import hashlib
import json
import os
import shutil
import sys

NEW_NAME = "pocketroot base"
NEW_ID = "pocketroot"
NEW_PRETTY = "pocketroot base (glibc)"
NEW_ORIGIN = "pocketroot"

# os-release 里要删掉的键：品牌 URL、logo 引用、发行版专属 codename 键
DROP_KEYS = {
    "HOME_URL", "SUPPORT_URL", "BUG_REPORT_URL", "PRIVACY_POLICY_URL",
    "LOGO", "UBUNTU_CODENAME", "DOCUMENTATION_URL",
}

# 要删的"纯标识"文件（allowlist，避免误删 alpine-release 这类被 apk 读取的文件）
IDENTITY_FILES = [
    "etc/alpaquita-release",
    "etc/ubuntu-release",
    "etc/redhat-release",
    "etc/system-release",
]

# 要删的目录内容（glob，相对 rootfs）
DELETE_GLOBS = [
    "etc/update-motd.d/*",
    "usr/share/pixmaps/*ubuntu*",
    "usr/share/pixmaps/*alpaquita*",
    "usr/share/pixmaps/*bellsoft*",
    "usr/share/backgrounds/*ubuntu*",
    "usr/share/backgrounds/*alpaquita*",
    "usr/share/icons/*ubuntu*",
    "usr/share/icons/*alpaquita*",
    "usr/share/plymouth/themes/ubuntu*",
    "usr/share/plymouth/themes/alpaquita*",
    "usr/share/applications/*ubuntu*",
    "usr/share/applications/*alpaquita*",
]

# 被当作"品牌"对待的名字。Debian 也在内：本项目基于 Debian 构建时同样不会
# 以 Debian 的名字分发（SPI 的商标政策比 Canonical 宽松，但把修改版称作
# Debian 仍不合适）。
#
# 注意 ID_LIKE=debian 是**功能字段**（指明包体系），不是标识，
# 因此 check() 里对 os-release 的扫描会跳过 ID_LIKE 行。
BRANDS = (b"ubuntu", b"alpaquita", b"bellsoft", b"debian")


def os_release_text(old: dict) -> str:
    """按固定顺序重排，只保留功能性键。"""
    lines = ['NAME="%s"' % NEW_NAME,
             "ID=%s" % NEW_ID]
    if "ID_LIKE" in old:
        lines.append("ID_LIKE=%s" % old["ID_LIKE"])
    if "VERSION_ID" in old:
        lines.append("VERSION_ID=%s" % old["VERSION_ID"])
        # VERSION 原先带发行版描述（如 "24.04.4 LTS (Noble Numbat)"），
        # 只保留版本号本身：数字不是品牌，也仍然可被脚本解析。
        lines.append('VERSION="%s"' % old["VERSION_ID"].strip('"'))
    if "VERSION_CODENAME" in old:
        lines.append("VERSION_CODENAME=%s" % old["VERSION_CODENAME"])
    lines.append('PRETTY_NAME="%s"' % NEW_PRETTY)
    if "LIBC_TYPE" in old:
        lines.append("LIBC_TYPE=%s" % old["LIBC_TYPE"])
    # 其余键原样带过去（未知键不丢，避免破坏别的工具），但**键名含品牌**
    # 的键一律丢弃：DEBIAN_VERSION_FULL、UBUNTU_CODENAME 之类。
    # ID_LIKE=debian 不在此列 —— 它是功能字段（指明包体系），不是标识。
    known = {"NAME", "ID", "ID_LIKE", "VERSION", "VERSION_ID",
             "VERSION_CODENAME", "PRETTY_NAME", "LIBC_TYPE"} | DROP_KEYS
    for k, v in old.items():
        if k in known:
            continue
        low = k.lower()
        if any(b.decode() in low for b in BRANDS):
            continue
        lines.append("%s=%s" % (k, v))
    return "\n".join(lines) + "\n"


def parse_kv(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def rewrite_os_release(rootfs: str) -> bool:
    """改真实文件：/etc/os-release 通常是 → ../usr/lib/os-release 的符号链接。"""
    for rel in ("usr/lib/os-release", "etc/os-release"):
        p = os.path.join(rootfs, rel)
        if not os.path.exists(p):
            continue
        real = os.path.realpath(p)
        cur = open(real, encoding="utf-8", errors="replace").read()
        new = os_release_text(parse_kv(cur))
        if cur == new:
            return False
        with open(real, "w", encoding="utf-8") as f:
            f.write(new)
        return True
    return False


def write_text(path: str, text: str, report) -> bool:
    if os.path.exists(path):
        try:
            if open(path, encoding="utf-8", errors="replace").read() == text:
                return False
        except OSError:
            pass
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    report["rewritten"].append(os.path.relpath(path, report["_root"]))
    return True


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


MANAGED_FILES = ["usr/lib/os-release", "etc/issue", "etc/issue.net",
                 "etc/motd", "etc/lsb-release", "etc/dpkg/origins/pocketroot"]

PRESERVED = [
    "/etc/apt/**（源与 keyring，装包要用）",
    "/usr/share/doc/**（版权与许可声明）",
    "/var/lib/dpkg/**、/lib/apk/db/**（包数据库）",
    "包名与源 URL（指名性使用，功能所必需）",
]


def collect_state(rootfs: str) -> dict:
    """清单记录的是**最终状态**而不是本次改动 —— 同一 rootfs 重复构建时，
    增量列表会变成空的，那样清单就失去审计意义。"""
    identity = {}
    for rel in ("usr/lib/os-release", "etc/os-release"):
        p = os.path.join(rootfs, rel)
        if os.path.exists(p):
            identity = parse_kv(open(os.path.realpath(p), encoding="utf-8",
                                     errors="replace").read())
            identity = {k: v.strip('"') for k, v in identity.items()}
            break
    files = []
    for rel in MANAGED_FILES:
        p = os.path.join(rootfs, rel)
        if os.path.exists(p):
            files.append({"path": rel, "sha256": sha256_file(os.path.realpath(p))})
    return {
        "identity": identity,
        "managed_files": files,
        "removed_policy": IDENTITY_FILES + DELETE_GLOBS,
        "preserved": PRESERVED,
    }


def debrand(rootfs: str, check_only: bool, manifest: str) -> int:
    if check_only:
        return check(rootfs)

    report = {"_root": rootfs, "rewritten": [], "deleted": []}

    if not os.path.exists(os.path.join(rootfs, "usr/lib/os-release")) and \
       not os.path.exists(os.path.join(rootfs, "etc/os-release")):
        print("[FAIL] 找不到 os-release，rootfs 不完整？")
        return 1

    if rewrite_os_release(rootfs):
        report["rewritten"].append("usr/lib/os-release")

    write_text(os.path.join(rootfs, "etc/issue"),
               NEW_PRETTY + " \\r on \\m (\\l)\n\n", report)
    write_text(os.path.join(rootfs, "etc/issue.net"),
               NEW_PRETTY + "\n", report)
    write_text(os.path.join(rootfs, "etc/motd"),
               NEW_PRETTY + " — unofficial build (modified rootfs)\n", report)
    write_text(os.path.join(rootfs, "etc/lsb-release"),
               "DISTRIB_ID=%s\nDISTRIB_RELEASE=1.0\n"
               "DISTRIB_DESCRIPTION=\"%s\"\n" % (NEW_ID, NEW_PRETTY), report)

    # dpkg 的 vendor 标识：新建一个、把 default 指过来。
    # 其它 origins 文件不删：它们只是参考数据，dpkg 只读 default。
    write_text(os.path.join(rootfs, "etc/dpkg/origins", NEW_ORIGIN),
               "Vendor: %s\n"
               "Vendor-URL: https://github.com/kiol4691/pocketroot\n"
               "Bugs: https://github.com/kiol4691/pocketroot/issues\n"
               "Parent: debian\n" % NEW_NAME, report)
    default = os.path.join(rootfs, "etc/dpkg/origins/default")
    if os.path.isdir(os.path.dirname(default)):
        cur = os.readlink(default) if os.path.islink(default) else None
        if cur is not None and cur != NEW_ORIGIN:
            os.unlink(default)
            os.symlink(NEW_ORIGIN, default)
            report["rewritten"].append("etc/dpkg/origins/default")
        elif cur is None and not os.path.exists(default):
            os.symlink(NEW_ORIGIN, default)
            report["rewritten"].append("etc/dpkg/origins/default")

    for rel in IDENTITY_FILES:
        p = os.path.join(rootfs, rel)
        if os.path.exists(p):
            os.unlink(p)
            report["deleted"].append(rel)

    for pat in DELETE_GLOBS:
        for p in sorted(glob.glob(os.path.join(rootfs, pat))):
            rel = os.path.relpath(p, rootfs)
            if os.path.isdir(p) and not os.path.islink(p):
                shutil.rmtree(p)
            else:
                os.unlink(p)
            report["deleted"].append(rel)

    print("[ok]   去品牌化：改写 %d 个文件，删除 %d 项"
          % (len(report["rewritten"]), len(report["deleted"])))
    for r in report["rewritten"]:
        print("         改  " + r)
    for r in report["deleted"][:10]:
        print("         删  " + r)
    if len(report["deleted"]) > 10:
        print("         删  ...（另有 %d 项）" % (len(report["deleted"]) - 10))

    if manifest:
        state = collect_state(rootfs)
        state["changed_this_run"] = {
            "rewritten": report["rewritten"],
            "deleted": report["deleted"],
        }
        with open(manifest, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, ensure_ascii=False)
        print("[ok]   清单已写出: " + manifest)
    return 0


def check(rootfs: str) -> int:
    """确认没有品牌残留。只扫「我们负责的文件」，避免把 apt 源、证书、
    /usr/share/doc 里的指名性引用误判成残留。"""
    bad = []
    targets = [
        "usr/lib/os-release", "etc/os-release", "etc/issue", "etc/issue.net",
        "etc/motd", "etc/lsb-release",
    ]
    for rel in targets:
        p = os.path.join(rootfs, rel)
        if not os.path.exists(p):
            continue
        text = open(os.path.realpath(p), encoding="utf-8", errors="replace").read()
        if rel.endswith("os-release"):
            # ID_LIKE 指明包体系（debian / alpine），属功能字段，不算标识残留
            text = "\n".join(l for l in text.splitlines()
                              if not l.strip().startswith("ID_LIKE="))
        data = text.lower().encode("utf-8", "replace")
        for b in BRANDS:
            if b in data:
                bad.append("%s 含 %r" % (rel, b.decode()))

    for rel in IDENTITY_FILES:
        if os.path.exists(os.path.join(rootfs, rel)):
            bad.append("%s 仍存在" % rel)

    for pat in DELETE_GLOBS:
        for p in glob.glob(os.path.join(rootfs, pat)):
            bad.append("%s 仍存在" % os.path.relpath(p, rootfs))

    if bad:
        print("[FAIL] 去品牌化残留 %d 项：" % len(bad))
        for b in bad[:20]:
            print("         " + b)
        return 1
    print("[ok]   去品牌化校验通过（无品牌残留）")
    return 0


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = [a for a in sys.argv[1:] if a.startswith("--")]
    if not args:
        print(__doc__)
        return 2
    rootfs = args[0]
    if not os.path.isdir(rootfs):
        print("[FAIL] rootfs 目录不存在: " + rootfs)
        return 1
    manifest = ""
    for f in flags:
        if f.startswith("--manifest="):
            manifest = f.split("=", 1)[1]
    return debrand(rootfs, "--check" in flags, manifest)


if __name__ == "__main__":
    sys.exit(main())
