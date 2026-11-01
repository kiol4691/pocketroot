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

## 随 rootfs 一起分发的 Python 包

由 `tools/add-wheels.py` 装进 rootfs（各自遵循原许可，本项目不重新授权）：

| 包 | 许可 |
|---|---|
| numpy、scipy、pandas | BSD-3-Clause |
| scikit-learn | BSD-3-Clause |
| matplotlib | matplotlib (PSF-based) |
| pillow | HPND |
| requests | Apache-2.0 |
| contourpy、kiwisolver、fonttools、joblib、threadpoolctl、packaging 等 | 各自许可（见 wheel 内 LICENSE） |

清单（含版本与 sha256）写在 rootfs 的 `/etc/pocketroot-wheels.json`。
若你把包换掉或增删，请同步更新这一节。

## 商标

本项目名称 `pocketroot` 与本文档无关的下列名称归各自权利人所有，本项目**不使用**它们
作为自身标识，也不声称与其存在隶属或背书关系：

| 名称 | 权利人 | 在本项目中的用法 |
|---|---|---|
| Ubuntu | Canonical Ltd. | 仅指明 glibc rootfs 的原始来源 |
| Alpaquita、BellSoft | BellSoft | 同上 |
| Alpine Linux | Alpine Linux 开发团队 | musl 变体 rootfs 的来源 |
| Debian | Software in the Public Interest | 指明包体系（dpkg/apt） |
| PyTorch、NumPy 等 | 各自基金会/公司 | 用户自行安装的运行期依赖 |

为避免修改版被误认为官方产物，构建时会处理发行版身份（`tools/rootfs-identity.py`）：

- **Debian 基线**：保留名称与版本，但明确标注为修改版（os-release 的 `VARIANT_ID`/
  `POCKETROOT_MODIFIED`、issue 与 motd 的告知行、`/etc/pocketroot-build.json`）。
  Debian 的商标政策允许「基于 Debian」的表述。
- **Alpaquita / Ubuntu 基线**：标识整体换成 `pocketroot base`，logo 与 motd 广告脚本删除。

包数据库、软件源、keyring、`/usr/share/doc` 下的版权声明**未改动** —— 其中出现的
原始名称属于指名性使用。

## 文档中的实证数据

`docs/` 下的验证记录由本项目作者实测得到，随代码一同以 MIT 授权；引用时请保留出处。
