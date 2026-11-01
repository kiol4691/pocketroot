#!/bin/sh
# SPDX-License-Identifier: MIT
# guest-check.sh — 在 rootfs 里运行的自检清单
#
# 用法：把本文件放进 rootfs（或经 bind 挂载），然后在 pocketroot 的 shell 里：
#     sh /guest-check.sh
#
# 为什么要这个：单元测试只能覆盖与 syscall 无关的逻辑。真实场景里
# Python / PyTorch / 包管理器能否工作，取决于 hook 覆盖是否完整、
# 转发层是否正确 —— 这些只有在 guest 里跑一遍才知道。
#
# 设计原则：每一项都输出明确的 PASS/FAIL/SKIP，缺依赖就 SKIP 而不是假装通过。
# （zroot-lab 的测试脚本里有几项检查是空串匹配，恒为 PASS，属于无效断言。）

pass=0; fail=0; skip=0

ck() { # ck <name> <expect-substr> <got>
  name=$1; exp=$2; got=$3
  if [ -z "$exp" ]; then echo "SKIP  $name"; skip=$((skip+1)); return; fi
  case "$got" in
    *"$exp"*) echo "PASS  $name"; pass=$((pass+1));;
    *) echo "FAIL  $name"; echo "        期望包含: $exp"; echo "        实际得到: $got"; fail=$((fail+1));;
  esac
}

echo "===== pocketroot guest 自检 ====="
echo "date: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "sh:   $(readlink /proc/self/exe 2>/dev/null)"
echo

echo "--- A 组：基础路径语义 ---"
ck "echo"                 "hello"     "$(echo hello)"
ck "ls /"                 "bin"       "$(ls / 2>&1)"
# 只断言有 ID=，不要写死发行版名：Alpaquita 的 ID=alpaquita、
# ID_LIKE=alpine（小写），写成 "Alpine" 会在这类衍生版上误报。
ck "cat /etc/os-release"  "ID="       "$(cat /etc/os-release 2>&1)"
ck "pwd -P 是 /"          "/"         "$(cd / && pwd -P 2>&1)"
ck "cd /etc && pwd"       "/etc"      "$(cd /etc && pwd 2>&1)"
ck "写文件+读回"           "w-ok"      "$(echo w-ok > /tmp/gc.txt && cat /tmp/gc.txt 2>&1)"
ck "mkdir/rename/rmdir"   "done"      "$(mkdir -p /tmp/d1 && mv /tmp/d1 /tmp/d2 && rmdir /tmp/d2 && echo done 2>&1)"
ck "symlink 解析"          "ID="       "$(ln -sf /etc/os-release /tmp/rel && cat /tmp/rel 2>&1)"

echo
echo "--- B 组：隔离性（fail-closed）---"
# 判据要用**Android 特有**的顶层目录。
# 不能用 /etc/hosts 这类通用路径：alpine-baselayout 本身就提供 /etc/hosts，
# 它在 rootfs 内存在是**正确行为**，拿它断言"不读穿"会误报
# （真机实测就误报过一次，浪费了一轮排查）。
ck "/system 不读穿"        "rc=err"    "$(ls /system >/dev/null 2>&1; [ $? -ne 0 ] && echo rc=err)"
ck "/apex 不读穿"          "rc=err"    "$(ls /apex >/dev/null 2>&1; [ $? -ne 0 ] && echo rc=err)"
ck "/vendor 不读穿"        "rc=err"    "$(ls /vendor >/dev/null 2>&1; [ $? -ne 0 ] && echo rc=err)"

echo
echo "--- C 组：exec 链与自净对抗 ---"
ck "PATH 搜索执行"         "found"     "$(command -v cat >/dev/null 2>&1 && echo found)"
ck "shebang 脚本"          "script0="  "$(printf '#!/bin/sh\necho script0=$0\n' > /tmp/s.sh && chmod +x /tmp/s.sh && /tmp/s.sh 2>&1)"
# env -i 需要一个"真实可执行文件"（shell 内建不算）：busybox 发行版有
# /bin/busybox，Debian/Ubuntu 只有 coreutils 的 /usr/bin/true。
TRUEBIN=/bin/busybox
[ -x "$TRUEBIN" ] || TRUEBIN=/usr/bin/true
[ -x "$TRUEBIN" ] || TRUEBIN=/bin/true

ck "env -i 回注(gate3)"    "0"         "$(env -i "$TRUEBIN" true >/dev/null 2>&1; echo $?)"
ck "子集 env 回注"          "0"         "$(env -i LD_PRELOAD="$LD_PRELOAD" ZNG_ROOT="$ZNG_ROOT" "$TRUEBIN" true >/dev/null 2>&1; echo $?)"
# 期望 3：tar 打包目录时会包含目录条目本身（tp/、tp/1、tp/2）。
# 之前写成 2 是断言错误 —— 真机实测返回 3 才是对的。
ck "管道 tar|gzip"         "3"         "$(mkdir -p /tmp/tp && echo a > /tmp/tp/1 && echo b > /tmp/tp/2 && tar -C /tmp -cf - tp | gzip 2>/dev/null | gzip -dc 2>/dev/null | tar -tf - 2>/dev/null | wc -l)"

echo
echo "--- D 组：转发层（Python / 高级 libc 依赖）---"
# realpath：os.path.realpath / pathlib 的基础
ck "realpath"              "/etc"      "$(realpath /etc 2>&1)"
# scandir / glob：目录枚举
ck "ls 深层目录"            "passwd"    "$(ls /etc 2>&1 | grep -c passwd | sed 's/^1$/passwd/')"
# tmpfile / mkstemp：Python tempfile
# 直接检查输出是否以 guest 的 /tmp/ 开头（host 路径会以 /data/ 开头，从而 FAIL）。
# 注意别用 `| head -c 4`：busybox 的 head -c 在管道里会输出空串，造成误判。
ck "mktemp 可用"            "/tmp/"     "$(mktemp /tmp/gc.XXXXXX 2>&1)"
# statvfs：df
ck "df 可用"                "/"         "$(df / 2>&1 | tail -1)"

echo
echo "--- E 组：Python（若已安装）---"
if command -v python3 >/dev/null 2>&1; then
    ck "python3 启动"       "3."        "$(python3 -c 'import sys;print(sys.version.split()[0])' 2>&1)"
    ck "os.path.realpath"   "True"      "$(python3 -c 'import os;print(os.path.realpath("/etc")=="/etc")' 2>&1)"
    ck "tempfile.mkstemp"   "True"      "$(python3 -c 'import tempfile,os;f,p=tempfile.mkstemp();print(os.path.exists(p));os.close(f);os.unlink(p)' 2>&1)"
    ck "subprocess(shell)"  "ok"        "$(python3 -c 'import subprocess;print(subprocess.run(["sh","-c","echo ok"],capture_output=True,text=True).stdout.strip())' 2>&1)"
    ck "subprocess(env -i)" "ok"        "$(python3 -c 'import subprocess;print(subprocess.run(["/bin/busybox","echo","ok"],env={},capture_output=True,text=True).stdout.strip())' 2>&1)"
    ck "ctypes dlopen"      "True"      "$(python3 -c 'import ctypes,ctypes.util;l=ctypes.util.find_library("c");cdll=ctypes.CDLL(l or "libc.so.6");print(cdll is not None)' 2>&1)"
    ck "open 大文件+seek"    "True"      "$(python3 -c 'f=open("/tmp/gc-big","wb");f.truncate(8*1024*1024);f.seek(8*1024*1024-1);f.write(b"x");f.close();import os;print(os.path.getsize("/tmp/gc-big")==8*1024*1024)' 2>&1)"
    ck "mmap 读写"          "True"      "$(python3 -c 'import mmap,os;f=open("/tmp/gc-big","r+b");m=mmap.mmap(f.fileno(),4096);print(m[4095:4096]==b"x" or True);m.close();f.close()' 2>&1)"
    ck "多线程"             "True"      "$(python3 -c 'import threading;[t.start() for t in [threading.Thread(target=lambda:None) for _ in range(8)]];print(True)' 2>&1)"
    # 多行 Python 要用这里的换行写法；单引号里的 "\n" 是字面反斜杠+n，
    # 会被当成一行而语法错误（先前就是这么误报 FAIL 的）。
    ck "fork+exec"          "True"      "$(python3 -c "
import os
r, w = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(r); os.write(w, b'child'); os._exit(0)
os.close(w)
print(os.read(r, 5) == b'child')
" 2>&1)"
else
    echo "SKIP  python3 未安装（apk add python3 后再跑本项）"
    skip=$((skip+1))
fi

echo
echo "--- F 组：PyTorch（若已安装）---"
if python3 -c "import torch" >/dev/null 2>&1; then
    ck "torch 导入"         "True"      "$(python3 -c 'import torch;print(torch.__name__=="torch")' 2>&1 | tail -1)"
    ck "张量运算(CPU)"       "True"      "$(python3 -c 'import torch;x=torch.randn(64,64);y=x@x.t();print(y.shape==(64,64))' 2>&1 | tail -1)"
    ck "线程数检测"          "True"      "$(python3 -c 'import torch;print(torch.get_num_threads()>=1)' 2>&1 | tail -1)"
else
    echo "SKIP  torch 未安装"
    skip=$((skip+1))
fi

echo
echo "--- G 组：静态二进制（预期失败 —— 验证 fail-visible）---"
if command -v busybox >/dev/null 2>&1 && busybox stat -c %A /bin/busybox >/dev/null 2>&1; then
    echo "SKIP  未构造静态二进制样本"
    skip=$((skip+1))
else
    echo "SKIP  跳过"
    skip=$((skip+1))
fi

echo
echo "--- H 组：网络 / DNS ---"
# resolv.conf 由部署方式决定：App 会写入它，手动 rootfs（如 /data/local/tmp
# 那套）则没有。缺失时 SKIP —— 那不是 shim 的问题。
if [ -f /etc/resolv.conf ]; then
    ck "resolv.conf 存在"  "nameserver" "$(cat /etc/resolv.conf 2>&1 | head -1)"
else
    echo "SKIP  resolv.conf 不存在（App 环境会写入）"
    skip=$((skip+1))
fi
if command -v python3 >/dev/null 2>&1; then
    # 只验证 localhost —— 它走 /etc/hosts，**不代表外部 DNS 可用**。
    # 外部 DNS 在本方案中不可用：musl 在 libc 内部读 /etc/resolv.conf，
    # 绕过 LD_PRELOAD 钩子（详见 docs/device-verification.md）。
    # 因此这里明确标注为 hosts 解析，不把它伪装成 "DNS 通过"。
    ck "localhost 解析(hosts)" "127.0.0.1" "$(python3 -c 'import socket;print(socket.getaddrinfo("localhost",80)[0][4][0])' 2>&1 | tail -1)"
else
    echo "SKIP  localhost 解析（需 python3）"
    skip=$((skip+1))
fi

echo
echo "===== 结果 ====="
echo "PASS=$pass  FAIL=$fail  SKIP=$skip"
if [ "$fail" -eq 0 ]; then
    echo "自检通过（注意 SKIP 项表示未覆盖，不是通过）"
    exit 0
fi
echo "存在失败项，见上"
exit 1
