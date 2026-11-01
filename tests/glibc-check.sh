#!/system/bin/sh
# SPDX-License-Identifier: MIT
# Alpaquita Linux (glibc) rootfs 在 pocketroot shim 下的验证
#
# 两个要点：
#  1. 初始启动要用 glibc 的 ld.so —— 内核无法解析 rootfs 内的
#     PT_INTERP=/lib/ld-linux-aarch64.so.1（Android 上不存在该路径）。
#     ld.so 会处理 LD_PRELOAD，于是 shim 随之加载。
#  2. **所有管道必须放在 guest 内部**（ash -c '... | head'）。
#     若写成  ash -c 'cmd' | head，那个 head 是**宿主的** toybox head
#     （bionic 动态链接），它会读到我们 export 的 LD_LIBRARY_PATH，
#     进而在 rootfs 的 /usr/lib 里找到 GNU ld script（libm.so 是文本），
#     报 "CANNOT LINK EXECUTABLE ... bad ELF magic"。
#     这是测试脚本的坑，与 shim 无关。
Z=/data/local/tmp/zng
R=$Z/aroot2
export LD_PRELOAD=$Z/libzng.so
export ZNG_PRELOAD=$Z/libzng.so
export ZNG_ROOT=$R
export ZNG_BINDS=$(printf '/dev\t/dev\n/proc\t/proc\n/sys\t/sys')
export LD_LIBRARY_PATH=$R/lib:$R/usr/lib
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LDSO=$R/lib/ld-linux-aarch64.so.1

echo "=== 1. 基本启动（关键：glibc 是否触发 rseq SIGSYS）==="
$LDSO $R/bin/ash -c 'echo hello-from-glibc' 2>&1
echo "rc=$?   (159=SIGSYS，说明被 seccomp 拦)"

echo
echo "=== 2. ls /（应看到 rootfs 的根）==="
$LDSO $R/bin/ash -c 'ls / | head -8' 2>&1

echo
echo "=== 3. 外部命令（exec 中继 + --argv0 协议）==="
$LDSO $R/bin/ash -c 'uname -a' 2>&1

echo
echo "=== 4. 读文件 ==="
$LDSO $R/bin/ash -c 'head -3 /etc/os-release' 2>&1

echo
echo "=== 5. 写文件 ==="
$LDSO $R/bin/ash -c 'echo w-ok > /tmp/w.txt && cat /tmp/w.txt' 2>&1

echo
echo "=== 6. 隔离性（/system 不应可见）==="
$LDSO $R/bin/ash -c 'ls /system 2>&1; echo rc=$?' 2>&1

echo
echo "=== 7. CPU/线程信息（glibc pthread，涉及 rseq/set_robust_list）==="
$LDSO $R/bin/ash -c 'nproc 2>&1; getconf _NPROCESSORS_ONLN 2>&1' 2>&1

echo
echo "=== 8. /proc bind ==="
$LDSO $R/bin/ash -c 'ls /proc/self/ 2>&1 | head -3' 2>&1

echo
echo "=== 9. 包管理器（glibc 版 apk）==="
$LDSO $R/bin/ash -c '/sbin/apk --version 2>&1' 2>&1

echo
echo "=== 10. 动态库加载（验证 /usr/lib 的 ld script 未干扰）==="
$LDSO $R/bin/ash -c 'ldd /bin/busybox 2>&1 | head -6' 2>&1
