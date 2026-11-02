# pocketroot

Android 上的 rootfs 路径重定向 shim（LD_PRELOAD，零 ptrace）。

本项目是同一作者三次重写的第三代：桌面版 **zroot** → Android 前作 **zroot-lab** → 本作。
目标不是"再写一个能跑的 PoC"，而是**把前两代的设计缺陷逐个消掉**，
并让核心算法第一次变得可验证。下文用 **A / B** 指代前两代（两者均未公开发布），
每一代被判死刑的设计与对应的修正见 [HISTORY.md](HISTORY.md)。

> 内部标识（`ZNG_*` 环境变量、`zng_` 符号前缀、`libzng.so`）沿用第二代的缩写，
> 与项目名解耦；改名不影响任何对外接口。

---

## 1. 设计原则（每一条都对应一个已定位的缺陷）

| # | 原则 | 针对的缺陷 |
|---|---|---|
| 1 | **显式传参，不用全局可变状态** | A 的 `zt_g` 是 524KB 全局 BSS（64 个 bind × 两个 `char[4096]`）；B 的 `z_mkbuf()` 是 24×4096 环形池 + 全局游标 `z_pi`，天然非线程安全 |
| 2 | **统一 `-errno` 返回** | A 里 `zt_translate` 返回 `1/0/-1`、`zt_host_guest` 返回 `0/1/-errno`，两套约定并存 |
| 3 | **输出缓冲由调用方提供、长度显式** | A 的 `zt_binds_serialize` 用 64KB 栈数组，溢出即**静默丢弃全部 bind**；B 的路径过长时**原样透传到 host**（把隔离漏洞伪装成成功调用） |
| 4 | **I/O 与解析分离，解析是纯函数** | A 的 `zt_elf_probe_fd()` 边读 fd 边解析，无法脱离内核单测 |
| 5 | **fail-visible：降级必须可观测** | A 的 `ZT_HOSTNATIVE` 把"rootfs 缺解释器"猜成"用 host libc 跑"，导致 ABI 不匹配的诡异崩溃；A 的 `zt_fixup_argv0` 找不到 argc 就静默放弃 |
| 6 | **errno 写入前检查符号存在性** | A 直接 `*__errno_location()` 解引用，符号缺失即 NULL 解引用崩溃（B 用 weak + 检查，这里沿用） |

## 2. 相对 A / B 的具体改动

**架构**

- **bind 表替代白名单**：B 的 `z_tr()` 是"顶层目录白名单 passthrough，其余一律重定向"，
  没有 bind、没有 `fake_root`、不处理 `..`。这里用统一的 bind 表，两个概念合并，
  默认 bind 由 App 通过 `ZNG_BINDS` 注入（shim 不硬编码 Android 目录，保持可测）。
- **双解析引擎**：`openat2(RESOLVE_IN_ROOT)` 主引擎 + 用户态降级。
  B 完全没有运行时符号链接解析，只能靠构建期改写 306 个 symlink；
  A 有双引擎但降级条件分散，这里显式化为 `should_fallback()`。
- **`openat2` 的 TOCTOU 收益**：`zng_open_guest()` 用**同一个 syscall** 完成解析与打开，
  消除了"先解析路径、再打开"的窗口。

**Android 平台对策**（`zng_hooks.c`）

| 对策 | A | B | pocketroot |
|---|---|---|---|
| setuid 家族 | 挂在 `fake_root` 条件下 | 无条件 return 0 | **无条件** return 0（凭证 syscall 是显式 BLOCKLIST，与是否伪造 root 无关） |
| statx(291) | 正常发 syscall（在 Android 上 shim 自己会 SIGSYS） | 返回 ENOSYS，把回退甩给调用方 | **用 fstatat 回填完整 statx**，功能不丢失，完全不发 291 |
| faccessat2(439) | 无此 hook | 返回降级 | 降级到 `faccessat`(48)，保留可支持的标志位 |
| musl 内部直接 syscall | 无对策 | 设备端每次解包打机器码补丁 | **构建期**打一次 + 生成清单，设备端只校验哈希 |

**musl 补丁时机**（`tools/patch-musl.py`）—— 这是相对 B 最大的流程改动：

```
B:      设备端，每次启动 → 扫描 700KB libc → 打补丁 → 命中数≠1 则不写盘（上层仍继续）
pocketroot: 构建期，一次性 → 打补丁 → 命中数≠1 即非零退出 → 生成 manifest → 设备端只校验 SHA-256
```

失败模式从"用户设备上的静默降级"变成"构建流水线上的硬失败"。

**日志**：B 0.1.8 把 `ZROOT_DEBUG` 常开打到 stderr，shell 输出与 relay 日志混在一起。
这里支持 `ZNG_LOG=<path>` 把 shim 日志写到独立文件，stderr 保持干净。

**argv[0]**：musl 的 ld.so 没有 `--argv0`，所以中继启动时程序看到的是 host 路径。
- A：栈上反向扫描找 argc（依赖未文档化布局，扫描 4096 槽，失败静默，且被 `|| 1` 强制对每个进程执行）
- B：不修
- pocketroot：**分级**。级别 1 改写 libc 的 `program_invocation_name` / `__progname` 全局指针
  （与栈布局无关，失败可检测，覆盖 `getprogname()`、错误输出等）；
  级别 2 栈回溯按编译开关 `ZNG_FIX_ARGV0_STACK` 可选开启，带多重校验且失败时日志可见。

## 3. 目录结构

```
shim/
  zng.h          公共定义（类型、errno、pathview、接口）
  zng_sys.h      syscall 号表（aarch64 + x86_64）与封装
  zng_core.c     纯逻辑：配置、路径翻译、ELF 解析、exec 计划  ← 可单测
  zng_run.c      解析引擎（双引擎）与 exec 执行
  zng_hooks.c    libc 钩子 + Android seccomp 对策
  zng_ctor.c     初始化、日志、argv0 分级修复
tests/
  test_main.c    核心逻辑单元测试（x86_64，可 ASan/UBSan）
tools/
  patch-musl.py  构建期 musl seccomp 补丁 + 清单生成
  patch-glibc-syscalls.py  构建期 glibc seccomp 补丁（改返回值语义）
  zprobe.c       静态探针：在 App 进程的 seccomp 下逐条试 syscall
  zthreads.c     线程密集压测（clone 回退 / TLS / 锁争用 / 条件变量），
                 两个变体各编一份：glibc 动态、musl 静态
app/             Android 测试终端
build.sh         全手动 APK 构建
```

## 4. 构建与测试

```bash
# 核心逻辑单元测试（不需要 Android 工具链）
make -C tests check      # ASan + UBSan

# APK（需要 zig cc、aapt2、ecj、d8、apksigner）
./build.sh            # Alpine (musl) 变体
./build.sh --glibc    # glibc 变体（默认 Alpaquita，可用 ROOTFS_TGZ 换 Ubuntu 等）

# 路径翻译热路径微基准（宿主机，不需要设备）
make -C tests bench && tests/bench_translate 200000
```

`build.sh` 会**先跑单元测试**再构建 —— 核心算法变了会立刻失败。

### 4.1 构建依赖

仓库**不内置**工具链（`tools/zig-*`、`tools/ecj.jar` 都在 `.gitignore` 里），需要自己准备。
全部依赖都是 x86_64 Linux 上的宿主工具，构建本身不需要 Android 设备。

| 依赖 | 版本 | 用途 | 获取方式 |
|---|---|---|---|
| JDK | 17+ | 跑 ecj / d8 / apksigner | `apt install openjdk-17-jdk` 或发行版对应包 |
| Android SDK | build-tools 33+ / platform 33+ | `aapt2` `d8` `zipalign` `apksigner` | Android Studio SDK Manager，或 `sdkmanager "build-tools;35.0.0" "platforms;android-35"` |
| Zig | **0.13.0** | 交叉编译 shim（`aarch64-linux-musl` / `aarch64-linux-gnu`） | <https://ziglang.org/download/0.13.0/>，解压即用 |
| Eclipse JDT 编译器 | 任意近期版本 | 编译 Java（不用 javac，见下） | <https://download.eclipse.org/eclipse/downloads/> 的 `ecj-*.jar`，或 Maven `org.eclipse.jdt:ecj` |
| Python | 3.8+ | 跑补丁脚本 `tools/patch-*.py` | 系统自带 |

**为什么是 Zig 0.13.0**：`build.sh` 用 `zig cc -target aarch64-linux-musl` 交叉编译一个
不链接 libc 的 shim，并依赖 0.13 版的 musl 头文件布局。换大版本前请先跑 `make -C tests check`。

**为什么用 ecj 而不是 javac**：build-tools 自带的 d8 处理 JDK 21 生成的匿名内部类会 NPE，
ecj 生成的 class 与 Android 工具链兼容性最好。

### 4.2 环境变量

`build.sh` 全部依赖都能用环境变量覆盖，默认值见脚本第 45–95 行：

```bash
export ANDROID_HOME=$HOME/Android/Sdk        # 或 ANDROID_SDK_ROOT
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk
export ZIG=/opt/zig-linux-x86_64-0.13.0/zig  # 默认 $BASE/tools/zig-linux-x86_64-0.13.0/zig
export ECJ=/opt/ecj.jar                      # 默认 $BASE/tools/ecj.jar
# 可选：BT / PLAT 指定 build-tools 与 platform；不设则取 SDK 里最新的
# 可选：ROOTFS_TGZ 指定 rootfs 压缩包（见下）
# 可选：KS 指定签名 keystore；不存在时会用 keytool 自动生成一个自签名（口令 znglab）
```

### 4.3 一条命令的最小流程

```bash
git clone <repo> && cd pocketroot
curl -LO https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz
tar -xf zig-linux-x86_64-0.13.0.tar.xz -C tools/
curl -L -o tools/ecj.jar https://repo1.maven.org/maven2/org/eclipse/jdt/ecj/3.38.0/ecj-3.38.0.jar

export ANDROID_HOME=$HOME/Android/Sdk JAVA_HOME=/usr/lib/jvm/java-17-openjdk
./build.sh                 # 产物: out/pocketroot-<ver>-arm64.apk
```

### 4.4 rootfs 来源

- `--musl`（默认）：`assets/alpine-rootfs.tar.gz`（仓库内，3.8 MB）
- `--glibc`（默认）：`assets/glibc-rootfs.tar.gz`（仓库内，BellSoft Alpaquita）
- 换别的发行版：`ROOTFS_TGZ=/path/to/rootfs.tar.gz ./build.sh --glibc`

glibc 变体推荐用 **Debian**（`trixie-slim`，或带 Python 的 `python:3.13-slim`）——
见 §7.2。仓库不内置它，构建时拉取（不需要 docker 二进制）：

```bash
# 带 Python 3.13 + pip 的 Debian 13（解包后约 148 MB，APK 约 43 MB）
python3 tools/pull-registry-rootfs.py docker.io/library/python:3.13-slim \
        -o /tmp/py313-slim-arm64.tar.gz
ROOTFS_TGZ=/tmp/py313-slim-arm64.tar.gz ./build.sh --glibc
```

```bash
python3 tools/pull-registry-rootfs.py docker.io/library/debian:trixie-slim \
        -o /tmp/debian-trixie-slim-arm64.tar.gz
ROOTFS_TGZ=/tmp/debian-trixie-slim-arm64.tar.gz ./build.sh --glibc
```

`pull-registry-rootfs.py` 也支持 GHCR（`ghcr.io/bell-sw/alpaquita-linux-base:stream-glibc`），
`--print-digests` 只打印 digest、不下载，便于把版本钉住在构建脚本里。

> 换 rootfs 时 `build.sh` 会用 tarball 的 SHA-256 作戳自动清理 stage；同名但内容不同的
> 场景不会被混在一起（早前手工清理踩过一次，已修）。

### 4.5 给 rootfs 补装 deb 与 Python 包

slim 镜像刻意裁掉了不少东西，其中 `libgomp1` 是 PyTorch CPU 后端的硬依赖。
装这些**不需要执行任何 arm64 代码**：deb 用 `dpkg-deb -x` 解包，wheel 本身就是个 zip，
所以在宿主机上直接完成。

```bash
# 补装 arm64 deb（默认：libgomp1 libatomic1 procps curl ca-certificates less file tzdata）
python3 tools/add-debs.py /tmp/rootfs --suite trixie

# 离线装 Python 包（按 cp313 + aarch64 挑选，解压进 site-packages，并对 .so 做架构自检）
python3 tools/add-wheels.py /tmp/rootfs --py 3.13 --arch aarch64 \
        --pkgs numpy,pandas,scipy,matplotlib,scikit-learn,pillow,requests

# 然后照常打包
tar -czf /tmp/rootfs.tar.gz -C /tmp/rootfs .
ROOTFS_TGZ=/tmp/rootfs.tar.gz ./build.sh --glibc
```

两个脚本都会把清单写进 rootfs（`/etc/pocketroot-debs.json`、`/etc/pocketroot-wheels.json`），
含包名、版本与 sha256。

### 4.6 轻量配方（轻度编码 + 日常办公）

默认只装「能干活」的最小集合，解包约 **343 MB**、APK 约 **98 MB**：

```bash
python3 tools/pull-registry-rootfs.py docker.io/library/python:3.13-slim \
        -o /tmp/py313.tar.gz                        # Debian 13 + Python 3.13 + pip
mkdir -p /tmp/rootfs && tar -xzf /tmp/py313.tar.gz -C /tmp/rootfs

# 工具链：git / 编辑器 / 压缩 / 网络 / 进程查看 / OpenMP
python3 tools/add-debs.py /tmp/rootfs \
        --pkgs git,less,file,procps,curl,ca-certificates,tzdata,vim-tiny,nano,zip,unzip,jq,openssh-client,libgomp1,libatomic1,make

# Python：数值 + HTTP + 办公文档
python3 tools/add-wheels.py /tmp/rootfs --py 3.13 \
        --pkgs numpy,requests,openpyxl,python-docx

# 瘦身（删 man/info/perl POD/python 测试/locale，**保留 copyright**）
python3 tools/slim-rootfs.py /tmp/rootfs

# 标注修改版并打包
python3 tools/rootfs-identity.py /tmp/rootfs --mode=mark
tar -czf /tmp/light-arm64.tar.gz -C /tmp/rootfs .
ROOTFS_TGZ=/tmp/light-arm64.tar.gz ./build.sh --glibc
```

体积构成（解包后）：

| 部分 | 大小 |
|---|---|
| Debian 13 + Python 3.13 + pip | 148 MB |
| + 54 个 deb（git 与其依赖占大头：git-core 25 MB、perl 约 34 MB） | +156 MB |
| − 瘦身（man / info / perl POD / python test / locale） | −29 MB |
| + numpy / requests / openpyxl / python-docx（含 lxml） | +15 MB |
| **合计** | **343 MB** |

不想带 git 的话去掉它和 `openssh-client` 能省约 80 MB（回到 260 MB 左右），
但 `git add -p` 之类依赖 perl 的功能也会一起没有。要做科学计算再把 scipy/pandas/
matplotlib 加上（+160 MB），见 §4.5。

## 5. 验证状态（诚实版）

**已验证**

- 核心逻辑 194 项断言，在 x86_64 上以 ASan + UBSan 通过（`make -C tests check`）：
  路径视图、翻译/反向翻译、`..` 语义、bind 最长前缀与上限、ELF 解析（含畸形输入）、
  env 构造（含 `envp==NULL` 回归）、exec 计划（musl / glibc / 未知加载器）。
- 全部 shim 源文件以 `-nostdlib -ffreestanding -Wall -Wextra` **零告警**编译通过
  （两个架构的 syscall 号表均参与编译）。
- x86_64 syscall 号表用 `_Static_assert` 与 libc 常量逐条对照。

**真机已验证**（Android 14 / arm64 真机，详见 `docs/device-verification.md`）

在 **App 进程**（装了 zygote seccomp 过滤器的真实环境）中三门禁全部通过：
`apk --version` 正常（gate1，W^X exec）、`readlink /proc/self/exe` 返回 guest 视图
（gate2）、`env -i` 自净对抗 rc=0 且子进程 `binds=3`（gate3）；
另有 shebang、写读、PATH exec、`/proc` bind、隔离性、`apk info` 全部 rc=0。

真机共暴露 **16 个 bug**，全部已修复并记录在 `docs/device-verification.md`
（含"为什么本机单测发现不了"）。其中最严重的是：无条件调用 `openat2` 做能力探测，
在 App 进程直接触发 SIGSYS —— **adb shell 里完全测不出来**，因为 adb shell
不是 app 进程、没有那套 seccomp 过滤器。

另有 4 个 bug（第 13–16 条）**只在 Ubuntu 上显形**：Alpaquita 的用户态是 busybox，
不调 `statx`、不用 fortified `readlink`、`mv` 走 `rename` 而非 `renameat2` ——
换一个发行版就把这三处全撞出来了。

**仍未验证**

- **arm64 syscall 号表无法自动校验**：`_Static_assert` 对照只在 x86_64 上做
  （测试跑在 x86_64）。真机上能跑通，间接说明用到的号都是对的，
  但表中未被实际使用的号仍未经校验。
- 16KB 页设备（Pixel 16K 开发者模式）。
- 换 glibc 版本（除 2.39 / 2.43 之外）时，补丁脚本的 EXPECT 命中数需重新确认 ——
  脚本会硬失败，这是设计意图而非缺陷。
- 只验证过 CPU 场景；没有 GPU / NNAPI 路径，也没有跑过完整的训练任务。

## 6. 已知限制

- **静态二进制可运行，但不经过 shim**：无 `PT_INTERP` 的 ELF 由内核直接加载，
  子进程因此**不做路径翻译**（`zng.log` 会记 `exec: static binary (child not shimmed)`）。
  压测程序 `zthreads` 的 musl 版就是静态的，它照样跑在 App 进程里、继承同一套
  seccomp，只是文件访问不翻译。要让它进 rootfs 视图，目前只能改成动态链接。
  不引入 ptrace 兜底：那是 A 里风险最高的 900 行，Android 上还受 SELinux 约束。
- **转发层已覆盖**：`fopen`/`freopen`/`opendir`、`realpath`/`canonicalize_file_name`/
  `get_current_dir_name`、`mkstemp` 家族（含 `mkostemps`）、`scandir`/`scandirat`、
  `glob`/`glob64`、`popen`/`pclose`/`system`、`posix_spawn`（含 `file_actions` 路径翻译）、
  `dlopen`（绝对路径）、`statvfs`、`truncate64`/`utimes`/`lutimes`。
  但 libc **内部**发起的调用（`__open`、`open_nocancel`）仍会绕过钩子，与 A/B 同限；
  `/etc/resolv.conf`、`/etc/passwd` 这类被 libc 内部读取的文件，只能靠 rootfs 内
  提供正确内容来"喂对"，无法拦截重定向。
- **不是安全沙箱**：这是路径重定向视图，不是权限隔离。guest 内进程仍以 app uid
  直接发起 syscall；未被钩住的 `syscall()` 直调、libc 内部读取（musl 的
  `getaddrinfo` / `getpwuid`）、`/proc` 都会穿透。**不要用它跑不可信代码。**
- `zng_resolve()` 的 `dirfd` 参数当前未使用（相对路径一律透传，内核基于 dirfd 解析
  本就正确）；仅当"dirfd 指向 rootfs 内且路径含需重定向的绝对符号链接"时才需介入。
- `rename`/`link` 两端跨 bind 时内核会正确报 `EXDEV`，不做跨设备模拟。

## 7. 许可与商标

本项目（代码 + 文档）以 **MIT** 授权，见 [LICENSE](LICENSE)。
每个源文件头部有 `SPDX-License-Identifier: MIT`。

### 7.1 发行版身份处理（两种模式）

分发的 glibc rootfs 是**修改版**（打了 seccomp 补丁）。构建时按基准发行版自动选模式
（`tools/rootfs-identity.py`）：

| 模式 | 适用 | 做法 |
|---|---|---|
| **mark** | Debian | **保留**发行版名称与版本，只明确告知是修改版：os-release 加 `VARIANT_ID=pocketroot`、`POCKETROOT_MODIFIED=1`，issue / motd 追加告知，并写出 `/etc/pocketroot-build.json` 与 `/usr/share/doc/pocketroot/README.md`（基准镜像、改了什么、如何复现） |
| **debrand** | Alpaquita / Ubuntu 等 | 把标识换成 `pocketroot base`：改写 os-release、issue、motd、lsb-release、dpkg origins；删除 logo、`/etc/<发行版>-release`、`/etc/update-motd.d/*`（其中 `50-motd-news` 还会联网） |

两种模式都**保留**：包数据库、`/etc/apt/**`（源与 keyring）、`/usr/share/doc/**` 下的
版权与许可声明。`dpkg -l` 里仍会看到 `ubuntu-keyring` 之类的包名 —— 那是指名性使用，
功能与合规所必需。

`--check` 会校验结果；`DEBRAND=0` 跳过（仅供对比原始镜像）；`IDENTITY=debrand|mark|none`
可强制指定模式。

> **Ubuntu** 是 Canonical Ltd. 的注册商标，**Alpaquita**、BellSoft 是 BellSoft 的商标，
> Debian 的商标归 Software in the Public Interest 所有。
> 本项目与它们均无关联，也未获其授权或背书；rootfs 里保留的原始包名仅用于指明来源。
> musl 变体（Alpine）当前**未**做去品牌化，仍是原样标识。

### 7.2 为什么 glibc 变体推荐 Debian 而不是 Ubuntu

两者的**标识文件**都能改干净，差别在改不掉的部分。实测（去品牌化后的统计）：

| | Ubuntu 24.04 base | Debian 13 (trixie-slim) |
|---|---|---|
| 文件名含品牌 | 15 | 54 |
| 但这些是 | `/etc/legal`（质保声明）、`/usr/share/apport`、`ubuntu-keyring`、sysctl.d 注释、`/etc/cloud/build.info`、libsystemd 内嵌串 | 几乎全是 `/usr/share/keyrings/debian-archive-*.gpg`（apt 验签必需）、`terminfo/xterm-debian`、`perl5/Debian`（模块命名空间） |
| 额外的发行版专属组件 | apport、ubuntu-advantage/Pro、update-manager、`50-motd-news`（联网抓取）、ESM 提示 | 无 |

即：Debian 剩下的全是**功能性**文件（keyring 改不动、perl 命名空间改不动），
Ubuntu 剩下的则包含会主动展示发行版身份的内容（`/etc/legal`、崩溃上报、
Pro 订阅提示、联网 motd）。

顺带确认了一个迁移前提：**补丁表在第三个 glibc 版本上仍然成立** ——
Debian trixie 的 glibc 2.41 与 Ubuntu 2.39、Alpaquita 2.43 的站点
（libc 里 `set_robust_list`×2、`rseq`/`clone3`/`faccessat2`/`statx` 各 1，
ld.so 里 `set_robust_list`/`rseq` 各 1）完全一致，`--check` 直接通过。

三代关系（A 桌面版 zroot / B Android 前作 zroot-lab / 本作 pocketroot）都是同一作者的
作品，A、B 均未公开发布，因此本项目不存在继承自第三方的代码或版权声明。

分发的 rootfs 资产里含有**被修改过的 libc**，以及 BusyBox 等 GNU 程序，
这部分不适用 MIT：

- 第三方组件清单与各自许可：[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
- 被修改二进制的源码获取方式：[SOURCE_OFFER.md](SOURCE_OFFER.md)

> 内部标识（`ZNG_*`、`zng_` 前缀、`libzng.so`）沿用第二代的缩写，与项目名解耦。
