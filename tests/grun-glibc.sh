#!/system/bin/sh
# SPDX-License-Identifier: MIT
# glibc(Alpaquita) rootfs 的对照运行器 —— 与 musl 版 run.sh 唯一区别是
# 显式经由 glibc 动态加载器启动。用法：
#   adb shell /data/local/tmp/zng/grun.sh 'sh /tmp/gc.sh'
# 详见 docs/device-verification.md「glibc rootfs（Alpaquita）验证」。
Z=/data/local/tmp/zng
R=$Z/aroot2
export LD_PRELOAD=$Z/libzng.so
export ZNG_PRELOAD=$Z/libzng.so
export ZNG_ROOT=$R
export ZNG_BINDS=$(printf '/dev\t/dev\n/proc\t/proc\n/sys\t/sys')
export LD_LIBRARY_PATH=$R/lib:$R/usr/lib
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
exec $R/lib/ld-linux-aarch64.so.1 $R/bin/ash -c "cd / && $1"
