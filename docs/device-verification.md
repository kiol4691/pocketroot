# 真机验证记录

设备：**JDY-AN00**，`arm64-v8a`，Android 14（API 34），内核 `5.15.104-android13`。
方式：无线调试（`adb pair` + `adb connect`），构建期补丁 + 手动 APK 构建。

## 结论

在 **App 进程**（即装了 zygote seccomp 过滤器的真实环境）中，三门禁全部通过：

```
--- gate1: W^X exec (apk) ---      apk-tools 2.14.9, compiled for aarch64.   rc=0
--- gate2: /proc/self/exe ---      /lib/ld-musl-aarch64.so.1                 rc=0
--- gate3: env -i 自净对抗 ---      （子进程 binds=3，注入与 bind 均生效）      rc=0
--- shebang ---                    sb-ok 0=/tmp/s.sh                          rc=0
--- write+read ---                 w-ok                                       rc=0
--- PATH exec ---                  uname -a 正常                               rc=0
--- /proc bind ---                 attr auxv cgroup                            rc=0
--- 隔离性 ---                      /system: No such file or directory         rc=0
--- 包管理器 ---                    apk info 列出 alpine-baselayout            rc=0
```

adb shell（非 App 环境）下额外验证：`ls /` 显示 rootfs 的根、`cat /etc/os-release`、
`readlink /proc/self/exe`、`pwd -P` = `/`、写文件回读、APK 中 306 个 symlink 改写、
musl 补丁 `@0x68810`（faccessat2→48）与 `@0x24de8`（statx→ENOSYS）。

## 真机暴露的 bug（本机单测全部无法发现）

按发现顺序。它们的共同点是：**都只在"真正发起 syscall / 真正解析二进制格式"时才暴露**，
而 x86_64 单元测试只覆盖纯逻辑。

### 1. `openat2` 能力探测在 App 进程直接触发 SIGSYS（最严重）

`zng_resolver_init()` 原先无条件调用 `openat2(437)` 探测能力。该 syscall 可能不在
Android app 的 zygote seccomp 白名单内 —— 被拦就是 SIGSYS，进程当场死亡，
**根本没有机会降级**。

症状极具迷惑性：`zng.log` 被创建（`zng_log_init` 已成功）却空无一物，
shell 起不来。**adb shell 里完全测不出来** —— adb shell 不是 app 进程，
没有那套 seccomp 过滤器。这正是本项目必须上真机的根本原因。

修复：默认不启用 Engine A，改用 Engine B；`ZNG_OPENAT2=1` 可显式启用（需先探测确认）。
Engine B 在本项目中是安全的：构建期已把 rootfs 内的**绝对** symlink 全改成**相对**，
内核解析相对链接不会逃出 rootfs。

### 2. `TarExtractor.writeFile` 未跳过 tar padding

写完 `size` 字节就返回，没有补到 512 字节边界，导致下一个 header 从数据中间开始读。
症状：`ls rootfs/` 输出的是文件内容而非文件名（如 `e nsswitch.conf file to
determine what`），目录名被截断成 `h` / `in`。

（之前的 `/data/local/tmp` 测试用系统 tar 解压，绕过了这段代码，所以没发现。）

### 3. `open` / `openat` 无条件读取可变参数 `mode`

第三个实参只在带 `O_CREAT`/`O_TMPFILE` 时存在，无条件 `va_arg` 会读到栈垃圾。
而内核 openat2 规定非 CREAT/TMPFILE 时 `how.mode` 必须为 0，否则 `EINVAL`。
症状：**写文件成功、读文件一律 "Invalid argument"**。

### 4. ELF 的 `PT_INTERP` 数据通常在 phdr 表之后

原本按 `span`（= phoff + phentsize*phnum）读取，随后 `zng_elf_interp()` 因
`off + fsz > n` 返回 `-EIO`。症状：**所有外部命令一律 I/O error**，而内建命令正常。

修复：拆成"先定位（`zng_elf_interp_loc`）+ 再定点读取"两步。

### 5. exec 程序路径误用了 symlink 解析

`zng_exec_core` 原先用 `zng_resolve`（解析 symlink）得到程序路径。
`/bin/ls` 解析后变成 `.../bin/busybox`，busybox 于是认为自己是 `busybox`，
转而去把 `argv[1]` 当 applet 名。症状：每条外部命令都报
`/: applet not found`、`-a: applet not found`。

修复：exec 路径改用 `zng_translate`（只做前缀翻译，保留 symlink）。

### 6. `zng_resolve` 与 `zng_translate` 返回值语义相反导致传错路径

`resolve` 的 0 表示"成功"，`translate` 的 1 才表示"已改写"。沿用旧三元
`(ir == 0) ? ihost : interp` 后，把 guest 路径当 host 路径传给加载器。
症状：`exec: relay /lib/ld-musl-aarch64.so.1`（缺 rootfs 前缀），外部命令 not found。

### 7. shebang 的解释器没有走 ldso 中继

解释器本身（busybox）是动态链接的，直接 `execve` 会让内核按真实根解析它的
`PT_INTERP` 而失败。症状：执行脚本 "not found"，但显式 `/bin/sh script` 正常。

修复：抽出公共 `exec_host()`，让"直接执行 ELF"和"shebang 解释器"共用同一套中继。

### 8. `ZNG_BINDS` 从未注入子进程

只在复制阶段跳过它，却忘了注入 —— 父进程 `binds=3`，exec 出的子进程 `binds=0`，
`/proc` `/dev` `/sys` 全部落到 rootfs 内的空目录。

## 环境相关的坑（非代码 bug）

| 现象 | 原因 | 处理 |
|---|---|---|
| `adb pair` 后设备列表为空 | 配对端口 ≠ 连接端口 | `adb mdns services` 查连接端口 |
| d8 报 R8 NPE（`String.length()`） | build-tools 33 的 d8 处理 JDK 21 生成的匿名内部类会崩 | 改用 ecj 编译 |
| javac 编译的 APK 里 `MainActivity$14.class` 出错 | 同上 | 同上 |
| logcat 抓不到 App 日志 | 该 ROM（MTK）屏蔽三方 App 的 logcat | 用 debuggable + `run-as` 读 `files/zng.log`、`files/shell.log` |
| `rm -rf out/stage` 触发批量删除保护 | rootfs 有 500+ 文件 | 改为覆盖式解压 |

## 复现方式

```bash
./build.sh
adb install -r out/pocketroot-0.1.0-arm64.apk

# 触发自检（结果落在 App 私有目录 files/shell.log）
adb shell am start -n com.pocketroot/.MainActivity --ez selftest true
sleep 40     # 若首次运行需解包 rootfs；python3 安装也会更慢
adb shell run-as com.pocketroot cat files/shell.log

# shim 自身的日志（resolver 引擎、exec relay、bind 数量）
adb shell run-as com.pocketroot cat files/zng.log
```

自检会自动执行 `sh /root/guest-check.sh`（构建期随 assets 打进 APK，解包时落到
rootfs 内），覆盖 A–H 组；并会尝试 `apk add python3`，以便真正覆盖 Python 组
（`realpath` / `tempfile` / `ctypes dlopen` / `subprocess` / `mmap` / 多线程 /
fork+exec）。无网络时该组 SKIP —— SKIP 表示未覆盖，不是通过。

`adb shell` 下的对照验证（绕过 App，直接验证 shim 与 rootfs）见 `tests/guest-check.sh`。

### 无线调试断开后的恢复

Android 在一段时间无连接后会**自动关闭无线调试**，且重新启用时**端口会变**
（配对端口 ≠ 连接端口，且每次都不同）。恢复步骤：

```bash
# 1) 手机上重新打开：开发者选项 -> 无线调试 -> 使用配对码配对设备
#    记下配对码与「IP 地址和端口」（这是配对端口）
adb pair <ip>:<配对端口>          # 输入配对码

# 2) 配对成功后，用 mDNS 发现真正的**连接**端口
adb mdns services
adb connect <ip>:<连接端口>       # 注意：与配对端口不同
```

配对信息会保留，所以只需重新 `pair` 一次；之后每次断开只要重新 `mdns` + `connect`。
若需长时间验证，建议改用 USB 调试（连接稳定、端口固定）。

## Python 与转发层验证（已通过）

guest 内 **Python 3.12.14** 正常运行（离线安装，绕开不可用的 DNS）。转发层
`zng_fwd.c` 的实战检验 **20/20 PASS**：

```
PASS  realpath              PASS  pathlib.resolve
PASS  tempfile.mkstemp      PASS  NamedTemporaryFile
PASS  ctypes dlopen(soname) PASS  ctypes dlopen(abs path)      ← 绝对路径必须经钩子翻译
PASS  subprocess            PASS  subprocess empty-env         ← execve 强制回注
PASS  subprocess PATH search
PASS  mmap rw               PASS  truncate size
PASS  threading x8          PASS  fork+waitpid
PASS  glob                  PASS  os.listdir / os.scandir
PASS  os.stat               PASS  os.statvfs
PASS  mkdir+write+read      PASS  rename
```

验证脚本：`tests/python-check.py`。

### 为什么需要离线安装（DNS 在 guest 内不可用）

```
nslookup: write to '127.0.0.1': Connection refused
wget: bad address 'dl-cdn.alpinelinux.org'
```

musl 的 `getaddrinfo` 在 **libc 内部**读取 `/etc/resolv.conf`（不走 PLT，
LD_PRELOAD 钩子截不到），读到的是 **Android 真实的** `/etc/resolv.conf`
→ `nameserver 127.0.0.1`。而 Android 的 DNS 走 netd 的 Unix socket，
不是 UDP 127.0.0.1，在 app 沙箱里不可达。

也就是说：**我们在 rootfs 里写的 `nameserver 8.8.8.8` 根本没被读到**。
这正是文档里列为已知限制的"libc 内部读取绕过 shim"，现已被真机证实。

绕过方式：在 PC 上解析 APKINDEX 求依赖闭包 → 下载 .apk → push 进设备 →
`apk add --allow-untrusted --no-network /tmp/pkgs/*.apk`。
（抓取脚本见下文"离线安装配方"。）

注：安装时**必须排除 musl 包**，否则会覆盖我们打过 seccomp 补丁的
`ld-musl-aarch64.so.1`，补丁丢失后在 App 环境会直接 SIGSYS。

## glibc rootfs（Alpaquita）验证（已通过，另暴露 4 个 bug）

同一 `libzng.so` 在 **glibc**（BellSoft Alpaquita，`ID_LIKE=alpine`）rootfs 上
跑同一套 `tests/guest-check.sh`：**PASS=20 FAIL=0**（5 个 SKIP 均为环境因素：
该镜像无 python3 包且 guest 无 DNS）。musl（Alpine）回归 **PASS=31 FAIL=0**。

这一轮再次印证"必须上真机"：以下 bug 在 musl 下**全部不可见**，切到 glibc
才显形。它们有一个共同模式 —— **glibc 对同一函数有独立的 *64 变体符号**，
musl 没有；只导出主符号时，请求变体的调用会静默落到 libc 原实现，路径
不翻译。

### 9. `mkstemp64` 等变体缺失：`mktemp` 报 "No such file or directory"

busybox 在 glibc 下请求 `mkstemp64`（musl 只请求 `mkstemp`）。落到 glibc
原实现后路径不翻译，去写 Android 的 `/tmp`。补导出 `mkstemp64 / mkostemp64 /
mkstemps64 / mkostemps64` 后修复。

### 10. `__open64_2` / `freopen64` 等 fortified 与 stdio 变体缺失：唯独 `cat` 打不开符号链接

- `cat` 走 fortified `__open64_2`（`_FORTIFY_SOURCE` 编译产物），当时落到
  libc 原实现 → 打到 Android 真实 `/etc` → ELOOP；
- 而 `head`/`wc` 走 `fopen`（我们有钩子）一切正常 —— 同一符号链接，
  唯独 cat 失败，迷惑性极强。

补导出 `__open_2 / __open64_2 / __openat_2 / __openat64_2 / openat64`、
`__xstat64 / __lxstat64 / __fxstatat64`、`freopen64`、`statfs / statfs64`、
`utime`、`mkfifo`（共 141 个导出符号）。

### 11. shim 无条件向 stderr 打日志，污染一切 `$(cmd 2>&1)`

`resolver: engine B ...` 每进程启动打一行，命令替换捕获的第一行永远是它，
真实输出被 `head -1` 截掉 —— 表现为各种命令"莫名返回空"。这正是本项目
批评 zroot-lab 的"日志污染 stderr"，自己重犯了一遍。改为仅 `ZNG_DEBUG=1`
时输出。

### 12. `O_LARGEFILE`(0x8000) 在该内核上令 symlink 解析返回 ELOOP（最隐蔽）

`ZNG_O_LARGEFILE` 照抄了 asm-generic 的 `0100000`。真机（JDY-AN00，
内核 `5.15.104-android13`）上裸 syscall 可稳定复现：

```
openat(AT_FDCWD, symlink路径, O_RDONLY)         -> 成功
openat(AT_FDCWD, symlink路径, O_RDONLY|0x8000)  -> ELOOP
```

普通文件不受影响 → `cat /etc/passwd` 一直正常；glibc 的 `fopen` 内部不带
此标志 → `head`/`wc` 正常；唯独走我们 `open64` 钩子的 `cat` 读符号链接失败，
报 "Too many levels of symbolic links"。musl/glibc 在 64 位平台的
`O_LARGEFILE` 都定义为 0 —— 我们照抄 32 位值是错的。修复：置 0。

**方法论**：定位靠的是 `LD_DEBUG=symbols,bindings`（看符号绑定到谁）+
给钩子加 `ZNG_DEBUG` 日志（看路径/flags/返回值）+ 裸 syscall 对照程序
（把"我们的封装"与"内核行为"两个变量拆开）。三层缺一不可。

### glibc 环境的运行方式（对照）

```bash
# grun.sh：与 musl 的 run.sh 唯一区别是显式走 glibc 的动态加载器
Z=/data/local/tmp/zng; R=$Z/aroot2
export LD_PRELOAD=$Z/libzng.so ZNG_PRELOAD=$Z/libzng.so ZNG_ROOT=$R
export ZNG_BINDS="$(printf '/dev\t/dev\n/proc\t/proc\n/sys\t/sys')"
export LD_LIBRARY_PATH=$R/lib:$R/usr/lib
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
exec $R/lib/ld-linux-aarch64.so.1 $R/bin/ash -c "cd / && $1"
```

## glibc rootfs 在 App 进程内（2026-11-01，HONOR JDY-AN00 / Android 14）

上一节所有结论都来自 **adb shell**，而 shell 进程的 `Seccomp: 0`（没有过滤器）。
真正要回答的问题是：glibc 能不能过 **zygote seccomp**。现在有答案了 —— 能，
但必须先做指令级补丁。

### 定位手段：`tools/zprobe.c`

`zprobe` 是静态 aarch64 探针，由 App 以 assets 拷到私有目录后 exec，因此**继承
App 的 seccomp 过滤器**（这是 adb shell 做不到的）。它逐条 fork 试 syscall，
被拦就是 SIGSYS —— 只发一条，死了不影响其它条。

实测被拦（Android 14 / 该 ROM）：

```
rseq 293   set_robust_list 99   clone3 435   futex_waitv 449
faccessat2 439   openat2 437
放行：getpid gettid mprotect getrandom statx membarrier prctl brk futex
      clone execve close_range newfstatat openat ...
```

### 打补丁：`tools/patch-glibc-syscalls.py`

与 `patch-musl.py` 同一思路（定位 `movz x8, #nr` → 把 `svc #0` 换成直接写返回值的
指令），但语义不同：`rseq / clone3 / faccessat2 / statx` → 返回 `-ENOSYS`（glibc 对
这四条都有显式 fallback），`set_robust_list` → 返回 0（返回值本来就没人看）。
每条 (文件, syscall) 的命中数都是**显式断言**，不符即构建失败。

### 三个只有真机才会暴露的坑

1. **窗口太窄会漏站点**。初始窗口 5 条指令时，`ld.so` 里 `set_robust_list`
   （`movz x8,#99` 之后夹了 7 条 str/stp 写结构体）没被匹配到 —— 而它恰好在
   `TCB allocated` 之后执行，于是补了 4 个站点后仍然 exit=159。窗口改 12 后命中。
2. **`NoShim` 对照必要**。用 `--ez noshim true`（不注入 LD_PRELOAD）复现，
   同样死在 `TCB allocated`，才排除"死在 shim"的猜想，把范围锁定到 glibc 自身。

3. **MOVN 的 `~imm` 语义差一（压测才炸出来）**。补丁把 `svc` 换成
   `movn x0, #38`，本意是 `x0 = -38 (ENOSYS)`，实际 `MOVN` 算的是 `~38 = -39`
   —— 那是 `ENOTEMPTY`。glibc 只在 `errno == ENOSYS` 时才回退到 `clone()`，
   于是 `pthread_create` 直接返回 "Directory not empty"，线程一个都建不起来。
   改成 `movn x0, #37`（`0x928004A0`）才正确。
   **门禁自检完全发现不了这个**（单线程路径不建线程），是线程压测第一跑就撞上的。

定位靠三层叠加，缺一不可：`LD_DEBUG=all`（走到哪一步）→ `zprobe`（哪条 syscall 被拦）
→ 静态码型扫描（哪条指令在发它）。

### 线程密集压测（`tools/zthreads.c`）

补丁改的三条行为全都与线程强相关（`clone3`→clone 回退、`rseq` 关闭、
`set_robust_list` 伪装成功），因此必须有专门的压测。`zthreads` 覆盖：

| 阶段 | 内容 | 压什么 |
|---|---|---|
| A/E/F | 反复 `pthread_create`/`join` + TLS 读写 + malloc churn | clone 回退、TLS 分配 |
| B | `pthread_detach` 后由系统回收 | 线程退出路径 |
| C | 64 线程抢同一把锁 | futex 快慢路径 |
| D | 生产者/消费者 `pthread_cond_wait` 握手 | futex 唤醒 |
| G | `pthread_key_create` + `setspecific` | TSD 析构 |

### 三方交叉对照

| 组 | 说明 |
|---|---|
| **glibc·patched** | `--glibc` APK，App 进程内（zygote seccomp），补丁后的 rootfs libc |
| **glibc·baseline** | adb shell（无 seccomp），未打补丁的 rootfs libc |
| **musl** | `--musl` APK，App 进程内，**静态**链接的 musl（见下方说明） |

```
                     32 线程 × 100 轮                       64 线程 × 200 轮
                     glibc·patched / baseline / musl        glibc·patched / baseline / musl
A/E/F 建销线程        169 / 204 / 223 ms                     736 / 745 / 902 ms   (3200 / 12800 个)
B     分离线程          8 /   5 /  10 ms                      15 /  13 /  25 ms
C     锁争用           17 /  17 /  24 ms                      31 /  36 /  43 ms   (6.4 万 / 12.8 万次加锁)
D     条件变量        165 / 187 / 167 ms                     317 / 387 / 347 ms   (1000 / 2000 次往返)
G     线程私有数据      7 /   6 /   5 ms                      11 /  12 /  12 ms
总计                 368 / 419 / 431 ms                    1113 / 1193 / 1332 ms  FAIL=0（三组）
```

重复采样（总计）：glibc·patched 362–368 / 1037–1113 ms；musl 431–438 / 1318–1332 ms。

结论：

- **`clone3` → `clone` 回退、`rseq` 关闭没有可测的性能退化** —— patched 组与未打补丁的
  基线同量级，差异小于采样噪声。12800 次线程创建回收、12.8 万次锁争用、
  2000 次条件变量往返，三组都是 `FAIL=0`。
- musl 组在线程创建回收上明显偏慢（902 vs 736 ms），但那是 **musl 与 glibc 的**
  线程原语差异，与本项目补丁无关；单机单次采样，不作性能结论。

**musl 组的条件说明**：musl 变体里的 `zthreads` 是**静态**链接（zig 自带 musl），
不是 rootfs 里那份 libc —— 交叉工具链没有可用的动态 musl sysroot。shim 对无
`PT_INTERP` 的 ELF 直接 `execve`（`zng.log` 会记 `exec: static binary (child not shimmed)`），
所以它照样跑在 App 进程里、继承同一套 seccomp。局限要说清楚：该子进程内部的路径
访问不经过 shim 翻译；本压测不做文件 I/O，因此不影响结论。

**已知降级（未在压测里量化，按补丁语义推断）**：`set_robust_list` 被伪装成功后，
内核侧没有健壮 futex 链，进程/线程崩溃时等待者拿不到 `EOWNERDEAD`，
依赖健壮互斥量做崩溃恢复的程序会**挂死而不是恢复**。要用这类语义时，
该站点不能补成"假装成功"，得换别的策略。

### 结果

```
./build.sh --glibc   # 产物 out/pocketroot-$VER-arm64-glibc.apk
```

App 内 selftest（`am start ... --ez selftest true`）：

```
Welcome to pocketroot
Alpaquita (glibc) aarch64 inside an Android app, via LD_PRELOAD path translation.
--- gate1: /sbin/apk --version ---  apk-tools 3.0.7-r1  rc=0
--- gate2: readlink /proc/self/exe ---  /usr/lib/ld-linux-aarch64.so.1  rc=0
--- gate3: env -i 自净对抗 ---  zng: active root=... binds=3 libc=glibc  rc=0
PASS=21  FAIL=0  SKIP=4
```

musl 变体回归：同样 PASS=21 FAIL=0 SKIP=4（改造未回归）。

## Ubuntu 24.04（glibc 2.39）验证（2026-11-01）

把 rootfs 换成 Ubuntu 24.04 base（`ubuntu-base-arm64.bin`，glibc 2.39）后，
**四个 bug 只在 Ubuntu 上显形**。Alpaquita 能过，是因为它的用户态是 busybox：
busybox 不调 `statx`、不用 fortified `readlink`、`mv` 走 `rename` 而不是 `renameat2`。

| # | 现象 | 根因 | 修法 |
|---|---|---|---|
| 13 | `ls`/`cat`/`stat` 一律 `*** stack smashing detected ***` | `struct zng_statx` 尾部写成 `u64 max + u32 min`，比内核的 `u32 min + u32 max` 大 16 字节 → 结构体 272 而非 256，`statx_fill()` 的 memset 越界写 | 按内核布局改回 256，并加 `_Static_assert` |
| 14 | `ls -l` 打成 `?rwx-wS--T ... Links: 41471`，`stat` 报 `weird file` | `struct zng_stat` 只写了 x86_64 布局（nlink 是 u64、mode 在前），arm64 是 `mode` 在前、`nlink` 只有 32 位 | 按架构分支定义，并断言 arm64 为 128 字节 |
| 15 | `ls -l /` 显示 `bin -> /system/bin`（宿主机路径） | coreutils 用 `_FORTIFY_SOURCE` 编译，`readlink` 被重定向到 `__readlink_chk`；这两个符号由 glibc 内部实现，没导出就不翻译路径 | 补导出 `__readlink_chk` / `__readlinkat_chk` |
| 16 | `mv` 报 `No such file or directory` | coreutils 的 `mv` 走 `renameat2`（带 RENAME_NOREPLACE），shim 只钩了 `renameat` | 补 `renameat2` 钩子（双路径翻译 + flags 透传） |

app 侧配套改动（这些不属于 shim，但没有 Ubuntu 跑不起来）：

- **shell 探测**：不再要求 `bin/ash` + `bin/busybox`，按 `ash → bash → sh` 取第一个可解析的；
- **multiarch 库路径**：glibc 的 `LD_LIBRARY_PATH` 增加 `/usr/lib/aarch64-linux-gnu`
  （Ubuntu 的运行时库都在这里，否则 bash 报 `libtinfo.so.6: cannot open shared object file`）；
- **门禁与包管理器解耦**：gate1 从"apk --version"改成"apk 或 dpkg"；guest-check 里
  `env -i` 用的可执行文件从写死 `/bin/busybox` 改为按序探测 `busybox → /usr/bin/true`；
- **隔离性判定**：coreutils 的 `ls` 对不存在路径返回 2（busybox 返回 1），断言改为"非 0 且无输出"。

**补丁表在 glibc 2.39 上原样通过**：libc 里 `set_robust_list` 2 处、`rseq`/`clone3`/`faccessat2`/
`statx` 各 1 处，ld.so 里 `set_robust_list`/`rseq` 各 1 处 —— 与 2.43（Alpaquita）完全一致，
说明那份"显式命中数"断言不是对着单一版本调出来的巧合。

结果（App 进程内，`--ez selftest true`）：

```
rootfs             glibc    结果
Ubuntu 24.04      2.39     PASS=21  FAIL=0  SKIP=4
Alpaquita         2.43     PASS=21  FAIL=0  SKIP=4
Alpine (musl)     —        PASS=21  FAIL=0  SKIP=4
```

构建方式（rootfs 用环境变量换，其余不变）：

```bash
ROOTFS_TGZ=/path/to/ubuntu-base-arm64.bin ./build.sh --glibc
```

> 换 rootfs 前要清掉 `out/stage-glibc`：脚本是覆盖式解压，不清会把上一个发行版的文件
> 留在树里，补丁脚本会因此报"命中 0 处"（这是它该有的行为 —— 硬失败，而不是悄悄跳过）。

## PyTorch 在 App 进程内跑通（2026-11-01）

环境：Ubuntu 24.04 rootfs + python 3.12 + **torch 2.5.1 CPU**（`manylinux2014_aarch64`
轮子，离线安装：宿主下好 10 个 wheel 推到 rootfs 里 `pip install --no-index`）。

| 场景 | 结果 |
|---|---|
| adb shell（无 seccomp） | `import torch` 正常，matmul 512²×20 = 0.159 s，autograd / conv2d 正常 |
| **App 进程（zygote seccomp）** | 一开始 `exit=159`；定位并修掉后 **同样全部通过**，matmul 0.238–0.328 s |

### 定位：`si_syscall` 是唯一能直接问内核的入口

`import torch` 死在第 3 个 `calling init`（`libopenblasp`）。torch 的 12 个 `.so`
全扫一遍，`movz x8,#N; svc` 里没有任何被拦号码 —— 说明调用点不在这些库里。
最后在 **shim 的 ctor 里装了一个 SIGSYS handler**，命中时读 `siginfo.si_syscall`
打印出来，一次性拿到答案：

```
zng: SIGSYS caught, si_syscall=235      # mbind（NUMA）
```

（Android 的 app seccomp 是白名单，全量探测 1..460 有 **247 个号码被拦**；
`mbind/get_mempolicy/set_mempolicy/migrate_pages/move_pages` 整族都在里面。）

### 为什么码型补丁救不了它

`patch-glibc-syscalls.py` 打在 `movz x8, #nr` + `svc` 这种**立即数**调用点上；
而 OpenBLAS 走的是 glibc 的通用 `syscall(nr, ...)` —— 号码在寄存器里，码型扫描
看不见。因此在 shim 里加了一个 `syscall()` 拦截，对 NUMA 这 5 个号码直接返回
`-1/ENOSYS`（"内核不支持 NUMA"），其余原样转发。OpenBLAS 收到 ENOSYS 就关掉
NUMA 优化继续跑。

### 大 rootfs 怎么进 App（踩过的三个坑）

torch 装完 rootfs 是 **718 MB**，不可能打进 APK，所以 app 支持
`--es rootfs <abs path>` 指向已有目录。坑：

1. `/data/local/tmp` 对 app 进程是 **EACCES**（untrusted_app 读不了 shell_data_file），
   但 `run-as` 能读 —— 于是变成"shell 侧打包、app 侧解包"：
   `tar -cf /data/local/tmp/rf.tar`（shell）→ `run-as ... tar -xf -`；
2. 直接在 `run-as` 里打包会丢所有 symlink（readlink 被拒），表现为 `/bin`、`python3` 全没了；
3. 复制到 `/sdcard` 行不通：FUSE 存储不支持符号链接，rootfs 的 194 个 symlink 全部失败。

外部 rootfs 不可用时 app **不会**回落到解包（否则会把 APK 里的 rootfs 解到用户指定目录，
覆盖原树 —— 实测踩过一次）。

### 已知限制

- 没装 numpy，torch 会打一条 `Failed to initialize NumPy` 警告，不影响计算；
- 只验证了 CPU 推理/训练原语（matmul、autograd、conv2d），没跑完整模型；
- `set_robust_list` 仍是"假装成功"，健壮互斥量崩溃恢复不可用（见前文）。

## 完整模型端到端：Mini RWKV-7 34.2M（2026-11-01）

上一节验证的是 torch 原语（matmul / autograd / conv2d）。这一节是**完整模型**：
加载真实预训练权重 → 前向 prefill → 自回归解码 → 复用 state 再算一次。

模型：`RWKV-Red-Team/Mini_RWKV_7_34.2M`（8 层 / 512 维 / 词表 6400，权重 66 MB）。
依赖刻意只装三个轮子：`numpy` + `tokenizers` + `rwkv`（**不用 transformers**，
tokenizer 直接用 `tokenizers.Tokenizer.from_file` 读 `tokenizer.json`，省掉一整坨依赖树）。

```
torch 2.5.1 threads 8
### RWKV-7 "Goose" enabled ###
Loading /root/minirwkv/rwkv-final-sft-2048 (cpu fp32)
loaded in 0.2s  layers=8 embd=512 vocab=6400
prompt_tokens 21 gen_tokens 48 time 6.29 s -> 7.6 tok/s
OUTPUT: The sudoku in one sentence is a commonly used format for a sentence. ...
next-token argmax: 6091
OK
```

即：**App 进程内（zygote seccomp 开着）跑完加载 + prefill + 48 token 解码，7.6 tok/s**，
第二次前向（复用 state）也正常。34M 的模型说胡话是模型能力问题，与运行时无关。

踩到的两个坑：

1. `rwkv` 包会**自己拼 `.pth`**（`torch.load(MODEL_NAME + ".pth")`），传带扩展名的
   路径会变成 `xxx.pth.pth`；
2. `rwkv`/`tokenizers` 的 `pip install` 默认依赖解析会去拉 `huggingface-hub` 等一串包，
   离线装必须 `--no-deps`（`tokenizers` 只有 `from_pretrained` 需要 hf-hub，
   `from_file` 不需要）。

关于 **Sudoku-RWKV**：HuggingFace 上不存在（`sudoku-rwkv` / `rwkv-sudoku` /
`sudoku rwkv` 全部 0 结果）。要跑真正的数独模型，把权重路径或 repo id 给出，
现有的 `--es rootfs <dir> --es run <cmd>` 通道可以直接接。

## 与 proroot 的性能对照（2026-11-01）

同一台设备（JDY-AN00 / Android 14）、**同一个 rootfs**（未打补丁的 Ubuntu 24.04 base）、
同一个 `/bin/bash`，都在 adb shell 下（无 seccomp）。pocketroot 走 `ld.so + LD_PRELOAD`（Engine B），
proroot 走它自己的 `libproroot.so -r rootfs -0 --link2symlink ...`。

| 负载 | pocketroot | proroot | 倍数 |
|---|---|---|---|
| `stat /usr/bin/bash` | 1.33–1.40 µs | 3.83–4.01 µs | **2.9× 快** |
| `open+close /usr/bin/bash` | 2.60–2.73 µs | 3.79–3.87 µs | 1.45× 快 |
| `access /etc/os-release` | 1.93–1.96 µs | 1.99–2.07 µs | 持平 |
| `fork+exec /bin/true`（120 次均值） | 4.14 ms | 14.19 ms | **3.4× 快** |
| `zthreads 32×100`（建销 3200 线程） | 420 ms | 461 ms | 1.10× 快 |
| `find /usr/lib -type f` ×10（各 1061 文件） | 221–257 ms | 376–380 ms | ~1.6× 快 |

`stat` 的 2.9× 差距来自**每次解析的 syscall 数**：pocketroot 默认走 Engine B（翻译 + 一次
`newfstatat`），proroot 每解析一条路径要多绕几圈。`access` 两者持平 —— 说明差距不在
字符串处理上，而在解析策略。

`exec` 的 3.4× 差距最明显：proroot 每条 exec 都重跑一遍它自己的 linker shim，
而 pocketroot 只做"读 ELF 头 → 找 PT_INTERP → 一次 `execve`"（见前文 16.3 → 5.3 那节）。

### 一个反向发现

拿**我们打过 seccomp 补丁的 rootfs** 给 proroot 跑，它直接崩：

```
Fatal glibc error: rseq registration failed
[proroot] SIGSEGV pc=0x... fault=0x7d00000477c code=-6
```

也就是说 proroot 依赖"原生"的 rseq 行为，而 pocketroot 的补丁方案（把 rseq 改成返回 ENOSYS）
和它的假设冲突。反过来，pocketroot 能吃下打过补丁的 rootfs —— 这正是 App 进程（带 zygote seccomp）
能跑 glibc/PyTorch 的前提。**两者不是同一个问题的两种解法，而是两种取舍**：
proroot 靠自己的运行时绕开限制，pocketroot 把 rootfs 改成对 seccomp 友好。

> 说明：proroot 是闭源二进制，这里只做"同样条件下谁快"的测量，不涉及实现细节。

## 常用库实战（2026-11-01）

在同一个 App 进程 rootfs 里离线装一批常用库（24 个 wheel，77 MB，`--no-index` 装），
**全部在 App 进程（zygote seccomp 开着）里跑通**：

| 库 | 版本 | 测试内容 | 耗时 | 结果 |
|---|---|---|---|---|
| numpy | 1.26.4 | 200×200 随机矩阵求逆 | 8.2 ms | ✓ |
| pandas | 2.2.3 | 20 万行 groupby 聚合 | 24.7 ms | ✓ |
| scipy | 1.14.1 | 300×300 LU 分解+求解、64K 点 FFT | 22.4 ms | ✓ |
| matplotlib | 3.9.2 | Agg 后端出图 | 130 ms | ✓ PNG 320×240 / 13.9 KB |
| scikit-learn | 1.5.2 | 4000×20 逻辑回归 | 596 ms | ✓ 准确率 0.999 |
| pillow | 10.4.0 | 画图 + 存 JPEG + 缩放 | 12.8 ms | ✓ JPEG 240×120 |
| requests | 2.32.3 | GET 宿主机 HTTP 服务 | 6.7 ms | ✓ 200 / 9998 B |

### 两个值得记的点

1. **numpy 版本是被 torch 钉住的**。torch 2.5.1 发布在 numpy 1.x 时代，所以这里保持
   numpy 1.26.4。代价是 matplotlib 3.9 会拉最新 `contourpy`(1.4.0)，而它要求
   `numpy>=2.0` —— 离线装会直接 `ResolutionImpossible`。解法是把 contourpy 钉到
   `1.3.3`（`numpy>=1.25`）。
2. **requests 的 DNS 走不通，IP 直连正常**。这不是网络问题：glibc 的解析器在
   **libc 内部**读 `/etc/resolv.conf`，不经过 shim 的钩子（见"已知限制"），所以
   拿到的是宿主机的 `/etc/resolv.conf`。访问 `http://<ip>:<port>` 完全正常，
   域名解析要么把 resolv.conf 内容喂进 rootfs 并被 libc 读到，要么走代理。

## 路径翻译热路径优化（2026-11-01）

`zng_translate` 是每个 open/stat/exec 都要过的纯 CPU 逻辑。先量再改：

```
make -C tests bench && tests/bench_translate 200000   # x86_64，-O2，每例取 5 轮最小值
```

| 用例 | 优化前 | 优化后 | 倍数 |
|---|---|---|---|
| `/usr/bin/busybox`（短路径） | 146.1 ns | 37.7 ns | **3.9×** |
| 128 字深路径 | 312.8 ns | 87.5 ns | **3.6×** |
| `/proc/self/status`（bind） | 102.2 ns | 36.8 ns | **2.8×** |
| `/`（根） | 108.1 ns | 13.4 ns | **8.1×** |
| 相对路径（不翻译） | 15.2 ns | 17.4 ns | 持平 |
| 含 `..`（走慢路径） | 149.2 ns | 138.7 ns | 持平 |

改了三处：

1. **规范路径快路径**：绝大多数路径没有 `.` / `..` / `//` / 尾斜杠，此时
   `pv_clean` 是恒等变换、逐组件 emit 等价于直接拼接 —— 判形后一次 memcpy 即可，
   省掉 pv_from（记录每组件偏移）+ pv_clean（带栈折叠）+ 每组件一次边界检查与 NUL 写。
2. **一趟扫描同时得到长度与规范性**（`zng_scan_abs`）：原来 strlen 与判形各扫一遍。
3. **8 字节整字 memcpy**：shim 不能依赖宿主 libc，原先只能逐字节循环，
   128 字符路径光拷贝就要几十纳秒。

`zng_comp_prefix` 用 cfg 里缓存的 `root_len` / `guest_len` 做组件边界匹配，不再 strlen 前缀。

### 优化过程本身抓到的两个 bug

1. **整字 strlen 会读过缓冲区尾部**。haszero 写法在单元测试里被 ASan 直接报
   `global-buffer-overflow`（字符串字面量正好卡在页尾）。改成"扫描时顺带算长度"，
   既省一趟又不会越界。
2. **判形条件少了 `run > 0`**，导致每个正常路径都因"长度 > 1"被判成不规范，
   快路径等于从未生效 —— 而单轮基准噪声有 2 倍，看数字还以为"优化生效了"。
   把基准改成**每例取 5 轮最小值** + 与 `/media` 原始副本做 A/B，才暴露出来。

### 设备端 A/B（`tests/zstat.c`，真机走 shim）

`ZNG_OPENAT2=0`（等价 App 内 openat2 被 seccomp 拦的情形），glibc rootfs：

```
                      旧 shim      新 shim
stat /usr/lib/libc.so.6   1.54 µs      1.47 µs   -4.5%
open+close /usr/bin/busybox 2.99 µs    2.75 µs   -8.0%
access /etc/os-release    2.26 µs      2.10 µs   -7.1%
```

绝对耗时被 syscall 主导（每次 1~3 µs），翻译省下的 ~100 ns 只占几个百分点 ——
这也说明**继续抠字符串不是方向**。

顺带量到一件更要紧的事：`ZNG_OPENAT2=1`（Engine A）时 `stat` 从 1.5 µs 涨到 **6.2 µs**，
因为每次解析要额外走 openat2 + readlinkat + close 三个 syscall。Engine A 默认关闭、
App 内又被 seccomp 拦，所以不影响现状；但若将来为了 TOCTOU 收益要打开它，
这笔 4× 的开销必须先算进来。

功能回归：单元测试 194 项（ASan+UBSan）全过；两个变体 App 内 selftest 均 `PASS=21 FAIL=0`。

### exec 路径的 syscall 压缩（2026-11-01）

上半节的翻译优化只省 CPU。真正占时间的是 syscall —— 而"每条命令启动前
shim 要花几个 syscall"是可以用计数直接证明的。

**计数设施**：`ZNG_COUNT=1` 打开，进程退出（destructor）或 **exec 之前**
把计数写进 `ZNG_LOG`：

```
zngcnt pre-exec pid=1234 56=2 63=1 57=2 221=1     # nr=count
```

`pre-exec` 那一行是必须的：`execve` 会替换整个进程映像，计数器随之消失，
第一次实现只挂 destructor，结果 exec 前的账全丢了（只数到 shell 自己的几个调用）。

**改了什么**（`shim/zng_run.c`）：

| 位置 | 改前 | 改后 |
|---|---|---|
| `exec_host` 读 ELF | `read_head(64)` + `read_head(span)` + `read_at(interp)`，**3 次 open** | 复用调用方已打开的 fd，1 次 read(4KB)，span 超限才在同一 fd 补读 |
| `zng_exec_core` 判类型 | `read_head(64)` + `read_head(512)`（2 次 open），读完就 close | 1 次 open + 1 次 read(4KB)，**fd 连同已读缓冲一起交给 `exec_host`**（所有权转移） |
| 解释器存在性 | 每条 exec 一次 `faccessat` | 去掉，让 `execve` 自己失败后再按 errno 诊断 |

**实测**（真机，`/bin/true` × N，每个 exec 之前的 shim syscall 数，10 次平均）：

```
syscall       旧      新
openat       5.0     2.0
close        4.0     1.0
read         4.0     1.0
faccessat    2.0     1.0
lseek        1.0     0.0
合计        16.3     5.3     -67%
```

其中 `faccessat 1.0` 已经是 **guest 自己发的**（ash 在 exec 前用 access 检查可执行位），
不是 shim 的开销。shim 侧现在只剩 open + read + close 三个 syscall —— 这是"必须
看 PT_INTERP 才能决定走 ldso 中继"的固有成本。

**为什么不做跨进程缓存**：缓存 PT_INTERP 看起来能把这 3 个也省掉，但 exec 是
fork 后在新进程里做的，父进程的缓存只在它自己 exec 前存在，子进程 exec 时缓存是空的；
要跨进程共享就得落到文件/共享内存，代价（open/mmap + 一致性）大于收益。

**为什么用计数而不是计时**：同一台机器上 `fork+exec` 本身约 5.7 ms（加载 ld.so +
2 MB libc），shim 省下的十几个 syscall（~10 µs）完全被淹没 —— 计时跑出来是噪声，
甚至出现"新版更慢"的假象。这类优化只能数，不能掐表。

下一步若要继续压，只能跳出"每次 exec 都读 ELF"这个前提（例如按 inode 缓存
到共享内存），属结构性改动，暂不做。


## 尚未验证

- PyTorch / `rseq` 风险（`docs/heavy-workloads.md`）—— 需先解决 glibc
  rootfs 的 python3 安装（Alpaquita 源不可达 + guest 无 DNS，需离线闭包）；
- 打补丁后 `clone3` 走 clone fallback、`rseq` 关闭，**线程密集/长跑**负载未压测；
- 换 glibc 版本后补丁的 EXPECT 命中数需要重新确认（脚本会硬失败，这是设计意图）。
