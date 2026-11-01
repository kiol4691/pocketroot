# 三代沿革：zroot → zroot-lab → pocketroot

README 里用 **A / B** 指代前两代，读者无从对应。这份文件按代记录：每一代**想解决什么**、
**哪条设计被判了死刑**、**下一代怎么改的**。每条判死刑的理由都能在本仓库的代码或
`docs/device-verification.md` 里找到对应，没有事后编造的叙事。

## 一览

| | **zroot**（A） | **zroot-lab**（B） | **pocketroot**（C，本作） |
|---|---|---|---|
| 目标平台 | 桌面 Linux | Android（免 root） | Android（免 root） |
| 形态 | rootfs 路径 shim | 同左 | 同左 |
| 内部标识 | `zt_` | `z_` / `ZROOT_*` | `zng_` / `ZNG_*` |
| 是否发布 | 未发布 | 未发布 | 本仓库 |
| 与下一代的关系 | 路线验证 | 平台验证 | 可验证性 |

三代共用同一条技术路线：**LD_PRELOAD 注入 + 路径翻译 + 零 ptrace**。
每一代都证明了路线可行，但留下的问题不同 —— 这正是重写三次的原因。

---

## A：桌面版 —— 证明了"不 ptrace 也能跑"，但结构不可测

**活下来的**：路线本身（LD_PRELOAD 而非 ptrace）、双解析引擎（`openat2(RESOLVE_IN_ROOT)`
为主 + 用户态降级为辅）、bind 的概念。

**被判死刑的**

| 设计 | 为什么必须去掉 |
|---|---|
| `zt_g`：**524 KB 全局 BSS**（64 个 bind × 两个 `char[4096]`） | 全局可变状态让每个函数都隐式依赖同一个对象，无法并发、无法单测 |
| 两套错误约定并存：`zt_translate` 返回 `1/0/-1`，`zt_host_guest` 返回 `0/1/-errno` | 调用方必须记住"哪个函数用哪套"，第 6 个 bug（见下）就是这个的直接后果 |
| `zt_binds_serialize` 用 64 KB **栈数组**，溢出即**静默丢弃全部 bind** | 降级不可见：用户看到的是"bind 没生效"，而不是"bind 太多" |
| `zt_elf_probe_fd()` 边读 fd 边解析 | I/O 与解析耦合，ELF 解析无法脱离内核做单元测试 —— 而 ELF 解析恰恰最容易出错 |
| `ZT_HOSTNATIVE`：把"rootfs 缺解释器"猜成"用 host libc 跑" | 把配置错误伪装成成功调用，最终以 ABI 不匹配的崩溃收场 |
| 直接解引用 `*__errno_location()` | 符号缺失即 NULL 解引用崩溃 |
| ptrace 兜底约 900 行 | 三代里风险最高的代码，且 Android 上还受 SELinux 约束 |

**教训**：能跑 ≠ 能验证。C 的第一原则"**解析是纯函数，I/O 与解析分离**"就是从
`zt_elf_probe_fd` 这条来的；"统一 `-errno`"是从两套约定并存来的。

---

## B：Android 前作 —— 证明了能进 App 进程，但把风险推到了设备端

**活下来的**：构建期把 rootfs 里的绝对 symlink 全改成相对（本作沿用，共 306 个）；
`errno` 写入前用 weak 符号检查；setuid 家族**无条件** return 0（凭证 syscall 是显式
BLOCKLIST，与是否伪造 root 无关）。

**被判死刑的**

| 设计 | 为什么必须去掉 |
|---|---|
| `z_tr()`：**顶层目录白名单 passthrough，其余一律重定向** | 没有 bind、没有 `fake_root`、不处理 `..`。两个概念（bind 与 root）混成一张白名单后，无法表达"/dev 走宿主、/usr 走 rootfs"这种常规需求 |
| `z_mkbuf()`：**24×4096 环形池 + 全局游标 `z_pi`** | 天然非线程安全；缓冲区寿命不明确，谁覆盖谁全靠约定 |
| 路径过长时**原样透传到 host** | 与 A 的溢出静默丢弃同类：把隔离漏洞伪装成成功调用 |
| **设备端**每次启动扫描 700 KB libc 打机器码补丁，命中数 ≠ 1 仍然继续 | 补丁失效的表现是"某条 syscall 偶发 SIGSYS"，且只在用户设备上发生；构建流水线对此一无所知 |
| `ZROOT_DEBUG` 常开、直接打 stderr（0.1.8） | 污染一切 `$(cmd 2>&1)`，shell 输出与 relay 日志混在一起 |
| 完全没有运行时符号链接解析 | 只能靠构建期改写目录树，遇到运行期新建/变化的链接就失效 |

**教训**：**失败要么在构建期硬失败，要么必须可观测**。C 的两条对应物：
`tools/patch-musl.py` / `patch-glibc-syscalls.py` 的"命中数显式断言 + 不符即非零退出 +
生成 manifest、设备端只校验 SHA-256"；以及 `ZNG_LOG=<path>` 把日志写进独立文件、
stderr 保持干净。

---

## C：pocketroot —— 把"能不能验证"当成第一需求

相对 A/B，C 的结构性变化只有三条，其余都是 Android 平台对策的细化
（细节见 README §1–§2，此处不重复以免两处维护）：

1. **解析是纯函数**：194 项断言在 x86_64 上以 ASan + UBSan 跑，不需要设备、不需要内核；
2. **构建期补丁 + 硬失败 + manifest**：补丁失效发生在构建机上，而不是用户设备上；
3. **fail-visible**：降级必须可观测（`ZNG_LOG` 独立文件、`ZNG_COUNT` 计数、
   SIGSYS handler 打印 `si_syscall`），不允许"猜一个能跑的行为"。

### 数字（截至 2026-11-01）

| 项 | 值 |
|---|---|
| shim 源码 | 4407 行（含 2 个头文件） |
| App（Java） | 1153 行 |
| 工具（探针 / 压测 / 补丁脚本） | 1227 行 |
| 测试与基准 | 1160 行 |
| 单元断言 | 194 项（ASan + UBSan，x86_64） |
| 真机暴露的 bug | **16 个**，逐条记在 `docs/device-verification.md` |
| 发行版覆盖 | Alpine(musl) / Alpaquita(glibc 2.43) / Ubuntu 24.04(glibc 2.39) |
| App 内 selftest | 三个变体均 `PASS=21 FAIL=0 SKIP=4` |
| 与 proroot 同条件对照 | `stat` 2.9× 快、`fork+exec` 3.4× 快 |

那 16 个 bug 是本项目最有价值的产出：**它们全部无法在 x86_64 单元测试里发现**，
要么需要真正发起 syscall，要么需要 zygote 的 seccomp 过滤器，要么需要一个
非 busybox 的用户态（第 13–16 条只出现在 Ubuntu 上）。这也是"必须上真机"的实证。

---

## 为什么 A / B 不发布

它们是同一条线上的中间产物，接口、命名、错误约定互不兼容，也没有验证记录。
把它们一起放出来，读者要在三个名字之间来回对照，而能得到的只有"历史版本的 bug"。
所以：**代码只留第三代，设计沿革留在这份文件里。**

## 关于名字

`zroot` 与 ZFS 的 `zroot` 池撞名（搜索结果全被占），`-ng` 又暗示"还有个在维护的前辈"
——而那个前辈并不存在。因此改名为 **pocketroot**：`root` 是搜索入口（"免 root 在
Android 上跑 Linux"），`pocket` 承接作者已有的 `pocket-agent` 这条产品线。

内部标识（`ZNG_*` 环境变量、`zng_` 符号前缀、`libzng.so`）**保留不改**：它只是
第二代的缩写，属于内部约定而非品牌，改动它没有任何外部收益。
