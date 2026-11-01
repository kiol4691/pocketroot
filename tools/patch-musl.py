#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
构建期 musl seccomp 兼容补丁
=============================

背景
----
Android 按 targetSdk 给 app 进程装 zygote seccomp allowlist。musl 1.2.4+ 内嵌
的两条 syscall 不在老白名单里：

    SYS_faccessat2 (439)   —— 一调用即 SIGSYS
    SYS_statx      (291)   —— 一调用即 SIGSYS

而 musl 内部是**直接发 syscall**，不经过 PLT，所以 LD_PRELOAD 钩子拦不住它
（这正是 zroot-lab 0.1.2 定位到的问题）。

对策：指令级降级——把 `movz x8, #N` 这条装载 syscall 号的指令改掉：

    movz x8, #439  (0xD28036E8)  ->  movz x8, #48    (0xD2800608)
        faccessat2 -> faccessat，参数布局完全一致，内核 ABI 兼容
    movz x8, #291  (0xD2802468)  ->  movz x8, #5000  (0xD2827108)
        statx -> 未实现的号，内核返回 ENOSYS，调用方自行回退

与 zroot-lab 的关键差异：补丁时机
---------------------------------
zroot-lab 在**设备端**每次解包后扫描并打补丁（MainActivity.patchLibcForSeccomp），
问题有三个：

  1. 每次启动都要扫一遍约 700KB 的 libc；
  2. 失败模式落在用户设备上 —— 命中数 != 1 就"不写盘"，上层却继续跑，
     最终表现为神秘的 exit=159，用户在现场无从判断（zroot-lab 0.1.3 的
     教训：补丁对着 symlink 静默 no-op，为此多花了一整轮调试）；
  3. 补丁正确性无法在发布前验证。

本脚本把补丁移到**构建期**：

  · 只需运行一次，产出的 rootfs 直接打包进 APK；
  · 命中数必须恰好为 1，否则非零退出 —— 在 CI 里就硬失败，不会流到用户手上；
  · 生成 manifest（记录补丁前后 SHA-256），设备端只做哈希校验，
    不匹配即明确报警，无需再扫描或修改文件。

失败模式因此从"用户设备上的静默降级"变成"构建流水线上的硬失败"。

用法
----
    python3 tools/patch-musl.py ROOTFS [--check] [--manifest out.json]

    --check     只校验不修改（用于 CI 断言补丁已正确应用）
    --manifest  写出 JSON 清单，供 App 端启动时校验

退出码
------
    0  成功
    1  补丁目标缺失 / 命中数不为 1 / 写盘校验失败
    2  参数错误
"""

import hashlib
import json
import os
import struct
import sys

# aarch64 指令（小端存储）
MOVZ_X8_439 = 0xD28036E8   # movz x8, #439   faccessat2
MOVZ_X8_48 = 0xD2800608    # movz x8, #48    faccessat
MOVZ_X8_291 = 0xD2802468   # movz x8, #291   statx
MOVZ_X8_5000 = 0xD2827108  # movz x8, #5000  -> ENOSYS

# musl 的 libc 可能以 symlink 形式存在（libc.musl-aarch64.so.1 -> ld-musl-...）。
# 必须按 realpath 去重后再打补丁，否则会出现"对着 symlink 打补丁却没生效"
# 或"同一个文件被打两次"两种情况。这是 zroot-lab 0.1.3 踩过的坑。
TARGETS = [
    "lib/libc.musl-aarch64.so.1",
    "lib/ld-musl-aarch64.so.1",
]

PATCHES = [
    (MOVZ_X8_439, MOVZ_X8_48, "faccessat2->faccessat"),
    (MOVZ_X8_291, MOVZ_X8_5000, "statx->ENOSYS"),
]


def le32(v: int) -> bytes:
    return struct.pack("<I", v)


def count_pattern(data: bytes, pattern: bytes) -> int:
    """统计字节序列出现次数（含重叠，逐字节滑动）。"""
    if not pattern:
        return 0
    n = 0
    start = 0
    while True:
        i = data.find(pattern, start)
        if i < 0:
            break
        n += 1
        start = i + 1
    return n


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve_unique_targets(rootfs: str):
    """按 realpath 去重后的真实文件列表。"""
    reals = []
    seen = set()
    for rel in TARGETS:
        p = os.path.join(rootfs, rel)
        if not os.path.exists(p):
            print(f"[warn] 缺失目标: {rel}")
            continue
        rp = os.path.realpath(p)
        if rp in seen:
            continue
        seen.add(rp)
        reals.append((rel, rp))
    return reals


def apply_patch(path: str, do_write: bool, report: dict) -> bool:
    """对单个文件应用全部补丁。返回是否成功。"""
    with open(path, "rb") as f:
        data = bytearray(f.read())

    name = os.path.basename(path)
    ok = True

    for old, new, label in PATCHES:
        old_b, new_b = le32(old), le32(new)
        hits = count_pattern(bytes(data), old_b)

        if hits != 1:
            print(f"[FAIL] {name}: {label} 命中 {hits} 处（预期 1）")
            report["patches"].append({
                "file": name, "patch": label,
                "hits": hits, "applied": False,
            })
            ok = False
            continue

        idx = data.find(old_b)
        data[idx:idx + 4] = new_b

        report["patches"].append({
            "file": name, "patch": label,
            "hits": hits, "applied": True, "offset": idx,
        })
        print(f"[ok]   {name}: {label} 命中 1，已改写 @0x{idx:x}")

    if not ok or not do_write:
        return ok

    # 写盘 + 回读校验（zroot-lab 也是这个思路，这里保留并加强）
    with open(path, "wb") as f:
        f.write(bytes(data))

    with open(path, "rb") as f:
        verify = f.read()

    for old, new, label in PATCHES:
        n_old = count_pattern(verify, le32(old))
        n_new = count_pattern(verify, le32(new))
        if n_old != 0 or n_new < 1:
            print(f"[FAIL] {name}: {label} 回读校验失败（旧 {n_old} 新 {n_new}）")
            ok = False
        else:
            print(f"[ok]   {name}: {label} 回读校验通过（旧 0 / 新 {n_new}）")

    return ok


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = [a for a in sys.argv[1:] if a.startswith("--")]

    if not args:
        print(__doc__)
        return 2

    rootfs = args[0]
    if not os.path.isdir(rootfs):
        print(f"[FAIL] rootfs 目录不存在: {rootfs}")
        return 1

    check_only = "--check" in flags
    manifest_path = None
    for f in flags:
        if f.startswith("--manifest="):
            manifest_path = f.split("=", 1)[1]

    targets = resolve_unique_targets(rootfs)
    if not targets:
        print("[FAIL] 没有可打补丁的 musl 二进制（rootfs 不完整？）")
        return 1

    print(f"补丁目标（去重后 {len(targets)} 个）:")
    for rel, rp in targets:
        print(f"  {rel} -> {rp}")

    report = {"rootfs": os.path.abspath(rootfs), "files": [], "patches": []}
    all_ok = True

    for rel, rp in targets:
        before = sha256_file(rp)
        file_ok = apply_patch(rp, do_write=not check_only, report=report)
        after = sha256_file(rp) if not check_only else before

        report["files"].append({
            "path": rel,
            "real": os.path.relpath(rp, rootfs),
            "sha256_before": before,
            "sha256_after": after,
            "patched": not check_only and file_ok,
        })
        all_ok = all_ok and file_ok

    if manifest_path and not check_only:
        with open(manifest_path, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"[ok]   清单已写出: {manifest_path}")

    print()
    if all_ok:
        print("musl seccomp 补丁: 全部通过" + ("（仅校验，未修改）" if check_only else ""))
        return 0
    print("musl seccomp 补丁: 存在失败项 —— 构建应当在此中止")
    return 1


if __name__ == "__main__":
    sys.exit(main())
