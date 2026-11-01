# Docker / PyTorch 可行性分析

先给结论，再给理由和做法。

| 目标 | 结论 | 原因 |
|---|---|---|
| **Docker 引擎**（dockerd / containerd / runc） | ❌ 不可能 | 需要 `CAP_SYS_ADMIN`，app 进程没有且拿不到 |
| **运行 Docker 镜像里的程序** | ✅ 可行 | 镜像层就是一堆 tar，解压成 rootfs 后与普通 rootfs 无异 |
| **PyTorch CPU 推理** | ⚠️ 可行但有硬约束 | 需要 glibc rootfs；无 CUDA；受内存限制 |
| **PyTorch GPU / CUDA** | ❌ 不可能 | Android 无 NVIDIA 驱动、无 CUDA runtime |

---

## 1. Docker 引擎：为什么不可能

Docker 不是"一个程序"，它是一组内核特性的编排。非 root 的 Android app 缺的是**内核能力**，不是实现：

| Docker 依赖 | 需要的权限 | app 能否获得 |
|---|---|---|
| `unshare(CLONE_NEWNS/NEWPID/NEWNET/NEWUTS/NEWIPC/NEWUSER)` | `CAP_SYS_ADMIN` | 否（无 root、无法 `setuid` 提权） |
| `mount()` / overlayfs / pivot_root | `CAP_SYS_ADMIN` | 否 |
| cgroups v1/v2（限制 CPU/内存） | 写 `/sys/fs/cgroup` | 否（属 system 组） |
| iptables / nftables（容器网络、端口映射） | `CAP_NET_ADMIN` | 否 |
| 设备节点 `/dev/*` | mknod + 权限 | 否 |
| 常驻 daemon | 需后台常驻 | Android 会杀后台进程 |

补充两点：

- **user namespace 也救不了**。虽然 `unshare(CLONE_NEWUSER)` 在部分内核上允许非特权用户调用（获得一个 namespace 内的 fake root），但 Android 内核普遍关闭了 `kernel.unprivileged_userns_clone`，且 `/proc/sys/kernel/unprivileged_userns_apparmor` 等策略会拒绝；即便成功，namespace 内的 root 也**不能**做真正的 `mount` overlayfs（需要真实文件系统支持）。
- **gVisor / runsc 之类的用户态运行时**理论上可行（纯用户态 syscall 拦截），但它自己就是个 ptrace/seccomp 内核模拟器，在 Android 上跑它等于把整个问题再套一层，且它需要的能力同样超出 app 沙箱。

**所以任何声称"在免 root Android 上跑 Docker 引擎"的方案，要么已 root，要么跑的不是 Docker。**

## 2. 运行 Docker 镜像：可行且实用

镜像本质 = 一份 rootfs + 一份配置（env / workdir / entrypoint）。我们没有 namespace，所以**不做隔离**，只做"目录 + 配置 + 进去执行"。

### 做法

在**构建期**（PC 上）完成转换，别在设备上做：

```bash
# 方案 A：skopeo + umoci（推荐，标准工具）
skopeo copy docker://pytorch/pytorch:2.1.0-cpu \
             oci:./image:latest
umoci unpack --image ./image:latest ./bundle

# 方案 B：手动（无工具时）
#   manifest.json -> config（env/entrypoint/cmd/workdir）
#   layers: 按顺序 tar -xzf 叠加到同一目录，whiteout 文件需处理
```

whiteout 处理是容易漏的一步：OCI 层里 `.wh.<name>` 表示删除下层文件，`.wh..wh..opq` 表示清空整个目录。不解这个，会出现"上层删了的文件又冒出来"。`umoci` 会处理，手动解包必须自己处理。

然后把配置落成启动脚本：

```sh
# 由 config.json 生成
export PATH=/usr/local/bin:...        # config.Env
export LD_LIBRARY_PATH=/usr/local/lib:...
cd /workspace                          # config.WorkingDir
exec /opt/conda/bin/python -c "..."    # config.Entrypoint + Cmd
```

### 限制（没有 namespace 的代价）

| Docker 语义 | 本方案 |
|---|---|
| 文件系统隔离 | 无。镜像 rootfs 就是一个目录，程序可以写出去（受 shim 的 fail-closed 限制，只能写到 rootfs 内） |
| PID 隔离 | 无。容器内 `ps` 看到的是 Android 的进程（/proc 是 bind 的） |
| 网络隔离 | 无。共享宿主网络栈，端口直接暴露 |
| 资源限制 | 无 cgroup。可用 `ulimit` 做软限制 |
| 多容器互联 | 无 bridge 网络，只能走 localhost |
| 镜像层复用 | 无，解包后是平铺目录 |

**结论：可以做"跑起来"和"分发"，不能做"隔离"。** 对"我要在手机上跑某个官方镜像里的程序"这个需求，这已经够了。

## 3. PyTorch：路径与硬约束

### 3.1 选 musl 还是 glibc

| | Alpine musl | Debian/Ubuntu glibc |
|---|---|---|
| 官方 PyTorch wheel（manylinux） | ❌ 加载不了（ABI 不兼容） | ✅ 直接可用 |
| Alpine 社区 `py3-torch` | ⚠️ 可用但版本滞后、包不全 | — |
| 需要的额外 syscall | 少（对 seccomp 友好） | 多（`rseq` 等，见下） |
| rootfs 体积 | ~5MB | 200MB–1GB+ |

**建议：要跑官方 PyTorch，用 glibc rootfs。** 我的 `zng_plan_build()` 已实现 glibc 的
`ld.so --argv0 A0 --library-path LIBS PROG ...` 协议（单测覆盖），
`zng_exec_core()` 会按 `PT_INTERP` 自动分派 musl/glibc，无需配置。

### 3.2 glibc 的 seccomp 风险（真实存在，务必先测）

glibc 比 musl 使用更多 syscall，其中几个可能不在 Android 老白名单里：

| syscall | 用途 | 风险 |
|---|---|---|
| `rseq` (293/334) | glibc 2.35+ 用于 TLS 快速路径 | 中。不在白名单即 SIGSYS |
| `set_robust_list` | pthread mutex 健壮性 | 低–中 |
| `getrandom` | 栈保护、ASLR | 低（较新内核白名单一般有） |
| `statx` | 由我们的 shim 用 fstatat 回填，**不会真的发出** | 已规避 |
| `faccessat2` | 降级到 `faccessat` | 已规避 |

**`rseq` 是关键风险点**：glibc 检测到内核不支持时会 fallback，但如果被 seccomp kill，它连 ENOSYS 都拿不到。

对策（按顺序尝试）：
1. 用 `zprobe` 先探测 `rseq` 是否被允许（在 shim 之外单独跑，死了不影响主链路）；
2. 若被禁，且 glibc 版本支持，用 `GLIBC_TUNABLES=glibc.pthread.rseq=0` 关掉（glibc 2.35+ 支持该 tunable）；
3. 仍不行，改用**旧版 glibc 的 rootfs**（2.31 及以前不强制 rseq）；
4. 最后才考虑对 rootfs 的 libc 打补丁（同 `tools/patch-musl.py` 的思路，但要新的模式表）。

### 3.3 其他硬约束

- **无 CUDA**。Android 设备没有 NVIDIA GPU，也没有 CUDA runtime。只能 CPU 推理。
- **内存**。PyTorch 加载模型 + 运行时常驻通常需要 1–2GB。Android app 的 native 内存上限因设备而异（通常 512MB–2GB，可通过 `android:largeHeap="true"` 提高 Java 堆，但对 native 无效）。大模型必然 OOM。
- **BLAS 与线程**。PyTorch 的 CPU 性能依赖 OpenBLAS/MKL 的线程并行。它会读 `/proc/cpuinfo` 决定线程数——由于 `/proc` 是 bind 到 Android 的，读到的是**真实 CPU 信息**，这反而是正确的（能识别大小核、NEON）。但可能过度订阅线程（把 E 核也算进去），建议显式设置 `OMP_NUM_THREADS`。
- **静态二进制**。部分工具（如某些 Rust 写的辅助程序）是静态链接，v1 会返回 `-ENOSYS`。PyTorch 本身是动态链接，不受影响。

### 3.4 推荐配置

```sh
# 启动前设置
export OMP_NUM_THREADS=4              # 避免过度订阅
export MKL_NUM_THREADS=4
export GLIBC_TUNABLES=glibc.pthread.rseq=0   # 若 rseq 被 seccomp 禁
export PYTORCH_NO_CUDA=1              # 明确走 CPU 路径
```

---

## 4. 落地检查清单

按此顺序验证，每一步失败都要先解决再往下：

```
[ ] 1. 选好 rootfs（musl 还是 glibc），能在 pocketroot shell 里 `ls /` 正常
[ ] 2. 跑 tests/guest-check.sh，A/B/C 组全 PASS
[ ] 3. zprobe 探测 rseq / set_robust_list / getrandom 是否被允许
[ ] 4. 装 python3，跑 guest-check.sh 的 E 组（realpath/tempfile/dlopen/subprocess）
[ ] 5. 装 torch，跑 F 组（导入 + 张量运算 + 线程）
[ ] 6. 若跑 Docker 镜像：PC 上 umoci 解包 -> 处理 whiteout -> 传进 rootfs
       -> 按 config.json 生成启动脚本 -> exec
```

第 2 步的 D 组（转发层）是 Python 场景的分水岭。本项目的 `zng_fwd.c` 已补齐
`realpath` / `mkstemp 家族` / `dlopen` / `posix_spawn` / `scandir` / `glob` /
`popen` / `system` / `statvfs` —— 这些是上一版缺失、会直接导致 Python 异常的部分。

---

## 5. 仍然存在的已知缺口

诚实列出，不要指望"基本无异常"能覆盖这些：

1. **libc 内部绕过 PLT 的读取**：musl 的 `getaddrinfo`（读 `/etc/resolv.conf`）、
   `getpwuid`（读 `/etc/passwd`）不走我们的钩子。缓解：保证 rootfs 内有正确的
   `/etc/resolv.conf` / `/etc/passwd` / `/etc/nsswitch.conf`，让它们读到"正确的内容"
   而不是穿透到宿主。（zroot-lab 的 README 也把这条列为已知限制。）
2. **`/proc` 与 `/sys` 是宿主的**：`ps`、`mount`、`/proc/self/maps` 看到的是 Android 视图。
   容器类工具（如 `nproc`、`free`）会给出宿主信息。
3. **静态二进制不支持**（v1 设计决定，见 README）。
4. **无 TOCTOU 保证**：除 `open` 用了 `openat2` 外，`stat`/`unlink`/`rename` 仍是
   "先解析路径、再发 syscall"的两步。
5. **网络不隔离**：容器里的服务会绑到宿主网络栈。
