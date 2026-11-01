# 源码获取说明（对应被修改的第三方二进制）

本项目分发的 rootfs 资产里，**libc 是被改过的**（为了在 Android 的 app seccomp 白名单下
运行）。GNU libc 是 LGPL-2.1、musl 是 MIT，但同一 rootfs 里还有 BusyBox(GPL-2.0)、
bash(GPL-3.0) 等 GNU 程序 —— 对这类二进制再分发，需要能够提供对应的源码。

本文件说明如何获得。

## 一、改动是什么

改动**不是**重新编译 libc，而是在**构建期对已编译的 libc 做指令级补丁**：

| 变体 | 脚本 | 改动内容 |
|---|---|---|
| musl | `tools/patch-musl.py` | `faccessat2`(439) → `faccessat`(48)；`statx`(291) → 未实现号 |
| glibc | `tools/patch-glibc-syscalls.py` | `rseq`/`clone3`/`faccessat2`/`statx` 的 `svc` 改成直接返回 `-ENOSYS`；`set_robust_list` 改成返回 0 |

两个脚本都是**确定性变换**：给定同样的输入 libc，输出的 SHA-256 固定，并写入
`assets/patch-manifest.json` 供 APK 内校验。

除 libc 外，rootfs 还被做了**去品牌化**（`tools/debrand-rootfs.py`）：改写
`/etc/os-release`、`/etc/issue`、`/etc/motd` 等标识文件，删除发行版 logo 与
motd 脚本，标识改为 `pocketroot base`。这一步同样由仓库内脚本完成，可复现；
清单写入 `assets/debrand-manifest.json`。**包数据库、软件源、keyring、
`/usr/share/doc` 下的版权声明不在修改范围内** —— 那是合规要求保留的部分。

## 二、修改的"源码"

对二进制补丁而言，"对应的源码"由两部分组成：

1. **变换本身**：仓库内的 `tools/patch-musl.py` / `tools/patch-glibc-syscalls.py`，
   加上脚本顶部注明的指令编码与命中数断言 —— 它完整描述了改了什么、改在哪里；
2. **原始输入**：上游发布的原始 libc 二进制及其源码（见下）。

复现方式：

```bash
# 1. 取上游 rootfs（示例：Alpine）
curl -O https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/alpine-minirootfs-3.22.1-aarch64.tar.gz
mkdir -p /tmp/r && tar -xzf alpine-minirootfs-3.22.1-aarch64.tar.gz -C /tmp/r

# 2. 施加本项目补丁（幂等、命中数不符会非零退出）
python3 tools/patch-musl.py /tmp/r --manifest=/tmp/manifest.json

# 3. 校验
python3 tools/patch-musl.py /tmp/r --check
```

glibc 变体把第 2 步换成 `tools/patch-glibc-syscalls.py` 即可。

## 三、上游源码位置

| 组件 | 源码 |
|---|---|
| musl libc | <https://musl.libc.org/releases.html>（Alpine 版本见 `aports/main/musl`） |
| Alpine 各包 | <https://git.alpinelinux.org/aports/> · 镜像 <https://dl-cdn.alpinelinux.org/alpine/> |
| glibc | <https://ftp.gnu.org/gnu/glibc/> |
| Alpaquita Linux | <https://bell-sw.com/alpaquita-linux/>（含源码获取方式） |
| Ubuntu / Debian 各包 | `apt-get source <包名>` · <https://archive.ubuntu.com/ubuntu/> |

## 四、联系

若上述方式仍无法取得你需要的源码，请在本仓库开 issue，我会补充对应的获取途径。
