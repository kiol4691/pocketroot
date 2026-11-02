#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# pocketroot APK 构建（全手动：zig cc + aapt2 + javac + d8 + zipalign + apksigner）
# 无 Gradle、无 root、无 Android Studio。
#
# 与 zroot-lab 构建流程的差异：
#   1. 构建前先跑核心逻辑单元测试（make -C tests check）—— 核心算法变了会
#      在这里就失败，而不是等到真机上出现 exit=159 才发现；
#   2. musl 的 seccomp 补丁在**构建期**由 tools/patch-musl.py 打，并把清单
#      打进 APK assets，设备端只校验（zroot-lab 是设备端打补丁）；
#   3. 打包进 APK 的是**打过补丁**的 rootfs（不是原始 tarball）。
set -euo pipefail

BASE="$(cd "$(dirname "$0")" && pwd)"
OUT="$BASE/out"
VER="${VER:-0.2.0}"

usage() {
    cat <<'EOF'
用法: ./build.sh [--musl|--glibc]

  --musl    构建 Alpine (musl) 变体（默认）
  --glibc   构建 Alpaquita (glibc) 变体

两者只差三处：打包的 rootfs 资产、构建期 seccomp 补丁（各自一套）、输出文件名。
glibc 变体额外处理发行版身份（见 tools/rootfs-identity.py）：Debian 只加修改版告知，其余整体去品牌化；musl 变体不做。
shim 与 Java 代码完全相同 —— 风味在运行时按「assets 里是哪个 tarball /
rootfs 里是哪个 ld.so」自动识别，不需要生成 BuildConfig。

环境变量覆盖：ANDROID_HOME / JAVA_HOME / BT / PLAT / ZIG / ECJ /
              ROOTFS_TGZ / KS / VER / DEBRAND
EOF
}

FLAVOR="${FLAVOR:-musl}"
while [ $# -gt 0 ]; do
    case "$1" in
        --glibc)   FLAVOR=glibc ;;
        --musl)    FLAVOR=musl ;;
        -h|--help) usage; exit 0 ;;
        *) echo "未知参数: $1"; echo; usage; exit 2 ;;
    esac
    shift
done

# ---- 依赖定位（可用环境变量覆盖）----
if [ -n "${JAVA_HOME:-}" ] && [ -x "${JAVA_HOME}/bin/java" ]; then
    PATH="${JAVA_HOME}/bin:$PATH"
fi
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/sdk}}"
# 兜底：Debian 侧常见的 ~/android-sdk
[ -d "$SDK" ] || SDK="$HOME/android-sdk"
ZIG="${ZIG:-$BASE/tools/zig-linux-x86_64-0.13.0/zig}"
# 未显式指定时取 SDK 里最新的 build-tools / platform，
# 免得把 33.0.2 这种具体版本写死。
BT="${BT:-$(ls -d "$SDK"/build-tools/* 2>/dev/null | sort -V | tail -1)}"
# compileSdk 只是**编译期** API 级别。
# 注意 targetSdk 仍保持 28（见 AndroidManifest.xml 注释）——那是**运行时**行为，
# 决定能否在 app 数据目录 exec 原生代码，两者互不影响。
PLAT="${PLAT:-$(ls -d "$SDK"/platforms/android-* 2>/dev/null | sort -V | tail -1)}"

# ---- 风味（musl / glibc）----
# 只有三处不同：rootfs 资产、是否打 musl 补丁、输出文件名。
# 两个变体用独立的 stage 目录，避免 rootfs 内容互相污染。
if [ "$FLAVOR" = glibc ]; then
    ROOTFS_ASSET="glibc-rootfs.tar.gz"
    ROOTFS_TGZ="${ROOTFS_TGZ:-$BASE/assets/$ROOTFS_ASSET}"
    APK_OUT="$OUT/pocketroot-$VER-arm64-glibc.apk"
    STAGE="$OUT/stage-glibc"
else
    ROOTFS_ASSET="alpine-rootfs.tar.gz"
    ROOTFS_TGZ="${ROOTFS_TGZ:-$BASE/assets/$ROOTFS_ASSET}"
    APK_OUT="$OUT/pocketroot-$VER-arm64.apk"
    STAGE="$OUT/stage"
fi
KS="${KS:-$OUT/zng.keystore}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "缺依赖: $1"; exit 1; }; }

echo "== [0/8] 核心逻辑单元测试 =="
# 不需要 Android 工具链 —— 只验证与架构无关的纯逻辑。
# 【zroot / zroot-lab 都缺这一层】，导致算法缺陷只能在设备上暴露。
make -C "$BASE/tests" check

echo "== [1/8] 检查工具链 =="
[ -f "$PLAT/android.jar" ] || { echo "缺 android.jar (PLAT=$PLAT)"; exit 1; }
[ -x "$BT/aapt2" ]         || { echo "缺 aapt2 (BT=$BT)"; exit 1; }
[ -f "$BT/lib/d8.jar" ]    || { echo "缺 d8.jar"; exit 1; }
[ -f "$ROOTFS_TGZ" ]       || { echo "缺 rootfs: $ROOTFS_TGZ"; exit 1; }
[ -x "$ZIG" ]              || { echo "缺 zig: $ZIG"; exit 1; }
# 用 ecj 编译 Java，而不是 javac：build-tools 33 自带的 d8(R8 3.3) 处理
# JDK 21 生成的匿名内部类会 NPE（"Cannot invoke String.length()..."）。
# ecj 生成的 class 与 Android 工具链兼容性最好。
ECJ="${ECJ:-$BASE/tools/ecj.jar}"
[ -f "$ECJ" ]              || { echo "缺 ecj.jar (ECJ=$ECJ)"; exit 1; }
need java
need python3
echo "  SDK=$SDK"
echo "  PLAT=$PLAT  BT=$BT  ZIG=$ZIG"

# 刻意不做 `rm -rf "$OUT/stage"`：rootfs 有 500+ 文件，整目录删除会触发
# 批量删除保护。采用覆盖式解压；需要彻底重建时手动删除 out/stage。
mkdir -p "$STAGE/assets"
# classes 必须每次清空：d8 会把目录下所有 .class 一起打包，
# 改包名后残留的 com/zroot/ng/MainActivity.class 就一直躺在 dex 里
# （实测：改名后 APK 里仍有旧包名的类与旧文案）。
rm -rf "$OUT/classes"
mkdir -p "$OUT/classes"

echo "== [2/8] 交叉编译 shim (aarch64-linux-musl) =="
# -nostdlib -ffreestanding：shim 不链接任何 libc，
# 运行时需要的 malloc/dlsym/__errno_location/environ 在加载时解析。
# 这是同一个 .so 既能注入 musl 也能注入 glibc 的前提。
# （-nostartfiles 对 zig cc 无效且会告警，故不传）
"$ZIG" cc -target aarch64-linux-musl \
    -shared -nostdlib -ffreestanding \
    -fno-stack-protector -fno-builtin -fPIC \
    -fvisibility=default -fno-strict-aliasing \
    -O2 -g -Wall -Wextra \
    -Wl,-soname,libzng.so \
    -o "$OUT/libzng.so" \
    "$BASE/shim/zng_core.c" \
    "$BASE/shim/zng_run.c" \
    "$BASE/shim/zng_hooks.c" \
    "$BASE/shim/zng_fwd.c" \
    "$BASE/shim/zng_ctor.c"
echo "  $(ls -la "$OUT/libzng.so" | awk '{print $5" bytes"}')"
echo "  导出符号: $(readelf --dyn-syms -W "$OUT/libzng.so" 2>/dev/null | awk '$4=="FUNC" && $7!="UND"' | wc -l) 个"
echo "  未定义(宿主提供): $(readelf --dyn-syms -W "$OUT/libzng.so" 2>/dev/null | awk '$7=="UND"{print $8}' | sort -u | tr '\n' ' ')"

echo "  zprobe:"
"$ZIG" cc -target aarch64-linux-musl -static -O2 -s \
    -o "$OUT/zprobe" "$BASE/tools/zprobe.c"
echo "  $(ls -la "$OUT/zprobe" | awk '{print $5" bytes"}')"

# zthreads：线程密集压测。**动态**链接对应风味的 libc（zig 交叉编译），
# 运行时由 guest 的 ld.so 解析到 rootfs 里的 libc —— 也就是被测的那份 libc。
# 两个变体各编一份，用来做 musl / glibc 的交叉对照。
echo "  zthreads ($FLAVOR):"
if [ "$FLAVOR" = glibc ]; then
    ZT_TARGET=aarch64-linux-gnu
else
    ZT_TARGET=aarch64-linux-musl
fi
"$ZIG" cc -target "$ZT_TARGET" -O2 -pthread -s \
    -o "$OUT/zthreads" "$BASE/tools/zthreads.c"
echo "  $(ls -la "$OUT/zthreads" | awk '{print $5" bytes"}')  interp=$(readelf -l "$OUT/zthreads" 2>/dev/null | grep -o "\[Requesting program interpreter: [^]]*" | cut -d: -f2)"

echo "== [3/8] 解包 rootfs + symlink 改写（"$FLAVOR"）=="
mkdir -p "$STAGE/rootfs"

# 覆盖式解压的前提是"同一个 rootfs"。换了发行版还留着旧 stage，
# 旧文件会和新文件混在一起 —— 补丁脚本于是报"命中 0 处"（因为它看到的是
# 上一次已经补过的 libc），看起来像脚本坏了。用 tarball 的 sha256 做戳：
# 不匹配就整个 rmdir 重建。
STAMP="$STAGE/.rootfs.sha256"
WANT_SHA="$(sha256sum "$ROOTFS_TGZ" | cut -d" " -f1)"
# 没有戳 = 老 stage（本次改动之前建的），同样视为不一致。
OLD_SHA="$(cat "$STAMP" 2>/dev/null || echo none)"
if [ -d "$STAGE/rootfs" ] && [ "$OLD_SHA" != "$WANT_SHA" ]; then
    echo "  stage 与 rootfs 不一致（${OLD_SHA:0:12} -> ${WANT_SHA:0:12}），清理重建"
    rm -rf "$STAGE"
    # assets/ 是第 2 步建的，这里整目录删掉后必须重建，否则后面的清单/脚本拷贝
    # 会写到一个不存在的目录（实测：换 rootfs 后 mark 模式写 manifest 直接 ENOENT）
    mkdir -p "$STAGE/rootfs" "$STAGE/assets"
fi
echo "$WANT_SHA" > "$STAMP"
tar -xzf "$ROOTFS_TGZ" -C "$STAGE/rootfs"

# (a) 内部绝对 symlink -> 相对 symlink。
#     符号链接由**内核**解析，不经过 LD_PRELOAD 钩子；rootfs 不在根位置时
#     /bin/ash -> /bin/busybox 会解析到宿主的 /bin/busybox 而失败
#     （zroot-lab 0.1.1 的故障，当时 306 个链接全部失效）。
#     这里改成相对路径，使 rootfs 位置无关。
python3 "$BASE/tools/rewrite-symlinks.py" "$STAGE/rootfs" | sed 's/^/  /'

# (a2) 发行版身份处理：分发的 glibc rootfs 是**修改版**（打了 seccomp 补丁）。
#      Debian 走 mark（保留名称 + 明确告知是修改版）；Alpaquita / Ubuntu 走
#      debrand（换成 pocketroot base，删 logo 与 motd 广告脚本）。
#      两种模式下包数据库、apt 源、/usr/share/doc 的版权声明一律保留
#      （功能与合规所需）。DEBRAND=0 可跳过（只用于对比原始镜像）。
if [ "$FLAVOR" = glibc ] && [ "${DEBRAND:-1}" != 0 ]; then
    # 模式按基准发行版自动选：Debian 保留名称、只加修改版告知（mark）；
    # 其余（Alpaquita / Ubuntu 等）整体换成 pocketroot base（debrand）。
    # 用 IDENTITY=debrand|mark|none 可强制指定。
    BASE_ID=$(sed -n 's/^ID=//p' "$STAGE/rootfs/usr/lib/os-release" 2>/dev/null \
              | head -1 | tr -d '"')
    [ -n "$BASE_ID" ] || BASE_ID=$(sed -n 's/^ID=//p' "$STAGE/rootfs/etc/os-release" 2>/dev/null \
                                   | head -1 | tr -d '"')
    case "$BASE_ID" in
        debian) IMODE=mark ;;
        *)     IMODE=debrand ;;
    esac
    IMODE="${IDENTITY:-$IMODE}"
    if [ "$IMODE" != none ]; then
        python3 "$BASE/tools/rootfs-identity.py" "$STAGE/rootfs" --mode=$IMODE \
            --manifest="$STAGE/assets/debrand-manifest.json" | sed 's/^/  /'
        python3 "$BASE/tools/rootfs-identity.py" "$STAGE/rootfs" --mode=$IMODE \
            --check | sed 's/^/  /'
    fi
fi

# (b) musl seccomp 补丁：构建期打一次并生成清单；命中数不为 1 会在此处
#     非零退出，不会把"补丁没生效"的 rootfs 带进 APK。
#     glibc 不适用 —— patch-musl.py 改的是 musl libc 里直接发 syscall 的
#     机器码，glibc 没有这段指令序列（命中数恒为 0）。
if [ "$FLAVOR" = glibc ]; then
    # glibc 同样要打 seccomp 补丁，但改的是**返回语义**而不是 syscall 号：
    # rseq / clone3 / faccessat2 / statx 改成返回 ENOSYS（调用方都有 fallback），
    # set_robust_list 改成假装成功（返回值本来就没人看）。
    # 依据是真机 App 进程里 zprobe 的实测结果，详见脚本顶部注释。
    python3 "$BASE/tools/patch-glibc-syscalls.py" "$STAGE/rootfs" \
        --manifest="$STAGE/assets/patch-manifest.json" | sed 's/^/  /'
else
    python3 "$BASE/tools/patch-musl.py" "$STAGE/rootfs" \
        --manifest="$STAGE/assets/patch-manifest.json" | sed 's/^/  /'
fi

# guest 端自检脚本一并打进 assets：App 解包时落到 rootfs 内，
# 于是 adb 触发一次 selftest 就能跑完整验证（含 Python 组），
# 无需手工 push、也不依赖 adb shell 的引号转义。
cp "$BASE/tests/guest-check.sh" "$STAGE/assets/"

# zprobe：静态 aarch64 探针，用来在 **App 进程**的 seccomp 环境里逐条试 syscall
# （adb shell 的 Seccomp=0，复现不了 glibc 的 exit=159）。静态链接，不依赖 rootfs。
if [ -f "$OUT/zprobe" ]; then cp "$OUT/zprobe" "$STAGE/assets/"; fi
if [ -f "$OUT/zthreads" ]; then cp "$OUT/zthreads" "$STAGE/assets/"; fi

echo "== [4/8] 重新打包 rootfs（$ROOTFS_ASSET）=="
# 关键：必须打包 $STAGE/rootfs（改写/补丁后的内容），
# 而不是把原始 ROOTFS_TGZ 拷进去 —— 否则设备端解出来的 libc 没打补丁，
# manifest 校验必然失败，且 musl 内部 faccessat2/statx 会直接 SIGSYS。
tar -czf "$STAGE/assets/$ROOTFS_ASSET" -C "$STAGE/rootfs" .
ls -la "$STAGE/assets/"

echo "== [5/8] aapt2 link + javac + d8 =="
"$BT/aapt2" link -o "$OUT/base.apk" \
    -I "$PLAT/android.jar" \
    --manifest "$BASE/app/AndroidManifest.xml" \
    -A "$STAGE/assets" \
    --auto-add-overlay

# ecj 的 -8 指定 Java 8 兼容级别；-bootclasspath 保证 android.* 来自
# android.jar，而不是 JDK 自带的 java.*。
java -jar "$ECJ" -nowarn -8 -encoding UTF-8 \
    -bootclasspath "$PLAT/android.jar" \
    -d "$OUT/classes" \
    "$BASE/app/MainActivity.java" "$BASE/app/TarExtractor.java"

java -cp "$BT/lib/d8.jar" com.android.tools.r8.D8 \
    --release --lib "$PLAT/android.jar" --min-api 24 \
    --output "$OUT" $(find "$OUT/classes" -name '*.class')

echo "== [6/8] 组装 APK =="
python3 - "$OUT/base.apk" "$OUT/unsigned.apk" "$OUT/classes.dex" "$OUT/libzng.so" <<'EOF'
import sys, zipfile
base, out_apk, dex, so = sys.argv[1:5]
zin = zipfile.ZipFile(base)
zout = zipfile.ZipFile(out_apk, 'w', zipfile.ZIP_DEFLATED)
for it in zin.infolist():
    zout.writestr(it, zin.read(it.filename))
zout.writestr('classes.dex', open(dex, 'rb').read())
zout.writestr('lib/arm64-v8a/libzng.so', open(so, 'rb').read())
zout.close()
print('assembled', out_apk)
EOF

echo "== [7/8] zipalign =="
"$BT/zipalign" -f 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"

echo "== [8/8] 签名 =="
if [ ! -f "$KS" ]; then
    keytool -genkeypair -keystore "$KS" -alias zng -keyalg RSA -keysize 2048 \
        -validity 10000 -storepass znglab -keypass znglab \
        -dname "CN=pocketroot, OU=pocketroot, O=pocketroot, C=CN"
fi
"$BT/apksigner" sign --ks "$KS" --ks-key-alias zng \
    --ks-pass pass:znglab --key-pass pass:znglab \
    --out "$APK_OUT" "$OUT/aligned.apk"
"$BT/apksigner" verify --print-certs "$APK_OUT" | head -4

echo
echo "== 完成 =="
ls -la "$APK_OUT"
