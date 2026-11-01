# 第三方组件说明

本仓库的**源代码**（`shim/`、`app/`、`tools/` 下自有文件、`tests/`、`docs/`、`build.sh`）
以 [MIT](LICENSE) 授权。下列第三方组件各自遵循其原许可，本项目的 MIT 不覆盖它们。

## 构建期依赖（仓库内）

| 组件 | 位置 | 许可 |
|---|---|---|
| Zig 工具链 0.13.0 | `tools/zig-linux-x86_64-0.13.0/` | MIT |
| Eclipse JDT 编译器（ecj.jar） | `tools/ecj.jar` | EPL-2.0 |

> `ZIG` / `ECJ` 都可以用环境变量指向系统里的版本，不必使用仓库内副本。

## rootfs 资产（会随 APK 一起分发）

### `assets/alpine-rootfs.tar.gz`（musl 变体）

Alpine Linux 基础根文件系统，包含多个组件，各自许可不同，其中主要的是：

- musl libc — **MIT**
- BusyBox — **GPL-2.0**
- apk-tools — **GPL-2.0**
- 其余包见 <https://pkgs.alpinelinux.org/packages>（按包名查许可）

**本项目会修改其中的 musl libc**（`tools/patch-musl.py`），见 [SOURCE_OFFER.md](SOURCE_OFFER.md)。

### `assets/glibc-rootfs.tar.gz`（glibc 变体，BellSoft Alpaquita）

BellSoft Alpaquita Linux 基础镜像。使用与再分发受 BellSoft 的条款约束
（<https://bell-sw.com/alpaquita-linux/>），使用前请自行确认；其内部组件同样包含
GNU libc（**LGPL-2.1**）与 BusyBox（**GPL-2.0**）等。

**本项目会修改其中的 glibc**（`tools/patch-glibc-syscalls.py`），见 [SOURCE_OFFER.md](SOURCE_OFFER.md)。

### 可选：Ubuntu / Debian rootfs

`./build.sh --glibc` 支持用 `ROOTFS_TGZ` 指向任意 glibc rootfs（如 Ubuntu base）。
这类镜像由大量 GPL/LGPL 组件构成，分发时同样适用各自的源码提供义务。
仓库**不包含**此类镜像。

## 运行期依赖（不随本项目分发）

使用者自行安装的 Python 包（numpy / torch / pandas / matplotlib …）遵循各自许可，
本项目既不分发也不重新授权它们。

## 文档中的实证数据

`docs/` 下的验证记录由本项目作者实测得到，随代码一同以 MIT 授权；引用时请保留出处。
