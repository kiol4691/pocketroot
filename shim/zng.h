/* SPDX-License-Identifier: MIT */
/*
 * zng.h — pocketroot 公共定义
 *
 * pocketroot：Android 上的 rootfs 路径重定向 shim（LD_PRELOAD，零 ptrace）。
 * 参考 zroot（桌面版 A）与 zroot-lab（Android 版 B）重写，针对性地修掉两者
 * 的设计缺陷。本节注释里的 [A-xxx] / [B-xxx] 标注了对应的原始缺陷。
 *
 * 设计原则（每一条都对应一个已知缺陷）：
 *
 *  1. 显式传参，不用全局可变状态
 *     [A] 全局 zt_g 524KB BSS，且 fake_root 等字段散落读写
 *     [B] 全局 z_pi 环形缓冲游标、z_fa_pool 文件动作池 —— 天然非线程安全
 *     => 所有函数显式接收 const struct zng_cfg *；cfg 在 ctor 里构建完毕后
 *        只读，因此多线程安全；路径缓冲由调用方提供（栈上），无共享游标。
 *
 *  2. 统一 -errno 返回，禁止 -1 / 0 / 1 混用
 *     [A] zt_translate 返回 1/0/-1，zt_host_guest 返回 0/1/-errno，两套约定并存
 *     => 一律返回负 errno；"是否改写"用独立的 out 参数或返回值枚举表达。
 *
 *  3. 输出缓冲由调用方提供，长度显式
 *     [A] zt_binds_serialize 用 64KB 栈数组，溢出即静默丢弃全部 bind
 *     [B] z_mkbuf() 24×4096 环形池，第 25 次调用覆盖第 1 次
 *     => 任何写缓冲的函数都带 outn 参数，不足即返回 -ENAMETOOLONG，绝不静默。
 *
 *  4. I/O 与解析分离，解析是纯函数
 *     [A] zt_elf_probe_fd() 边读 fd 边解析，无法脱离内核单测
 *     => zng_elf_span() / zng_elf_interp() 只吃内存 buffer，可 100% 单测。
 *
 *  5. fail-visible：任何降级都必须可观测
 *     [A] ZT_HOSTNATIVE 把"rootfs 里找不到解释器"猜成"用 host libc 跑"，
 *         导致 ABI 不匹配的诡异崩溃
 *     [B] 补丁命中数 != 1 时"不写盘"但上层仍继续
 *     => 宁可返回 -ENOSYS 让上层明确失败，也不猜。
 *
 *  6. errno 写入前检查符号是否存在
 *     [A] *__errno_location() 直接解引用，无 weak、无空检查
 *     => weak 声明 + 地址检查（沿用 B 的正确做法）。
 */
#ifndef ZNG_H
#define ZNG_H

#include <stddef.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* 常量                                                                */
/* ------------------------------------------------------------------ */

#define ZNG_PATH_MAX  4096
#define ZNG_MAX_COMPS 64      /* 路径最多组件数（A 用 128，64 足够且更省栈） */
#define ZNG_MAX_BINDS 64

/* exec 引擎对目标文件的分类 */
#define ZNG_ELF_DYNAMIC  0    /* 动态链接，interp 已填充            */
#define ZNG_ELF_STATIC   1    /* 静态链接（无 PT_INTERP），v1 不支持 */
#define ZNG_NOT_ELF      2    /* 非 ELF（脚本/数据），交给 shebang  */

/* 加载器种类 —— 决定 argv 构造协议 */
#define ZNG_LD_MUSL   1
#define ZNG_LD_GLIBC  2
#define ZNG_LD_OTHER  3

/* ------------------------------------------------------------------ */
/* errno（Linux 通用值，各 arch 一致）                                  */
/* ------------------------------------------------------------------ */

#define ZNG_EPERM          1
#define ZNG_ENOENT         2
#define ZNG_EINTR          4
#define ZNG_EIO            5
#define ZNG_EBADF          9
#define ZNG_EAGAIN        11
#define ZNG_ENOMEM        12
#define ZNG_EACCES        13
#define ZNG_EFAULT        14
#define ZNG_EEXIST        17
#define ZNG_EXDEV         18
#define ZNG_ENOTDIR       20
#define ZNG_EISDIR        21
#define ZNG_EINVAL        22
#define ZNG_ENFILE        23
#define ZNG_EMFILE        24
#define ZNG_ENOTTY        25
#define ZNG_ESPIPE        29
#define ZNG_EROFS         30
#define ZNG_EMLINK        31
#define ZNG_EPIPE         32
#define ZNG_ENAMETOOLONG  36
#define ZNG_ENOSPC        28
#define ZNG_ENOSYS        38
#define ZNG_ELOOP         40
#define ZNG_EOVERFLOW     75
#define ZNG_ENXIO          6
#define ZNG_ECHILD        10
#define ZNG_EBUSY         16
#define ZNG_ENOEXEC        8
#define ZNG_ERANGE        34

/* ------------------------------------------------------------------ */
/* open / AT_* / statx 标志                                            */
/* ------------------------------------------------------------------ */

#define ZNG_O_RDONLY      00
#define ZNG_O_WRONLY      01
#define ZNG_O_RDWR        02
#define ZNG_O_CREAT      0100
#define ZNG_O_EXCL       0200
#define ZNG_O_TRUNC      01000
#define ZNG_O_APPEND     02000
#define ZNG_O_NONBLOCK   04000
#define ZNG_O_DIRECTORY  0200000
#define ZNG_O_NOFOLLOW   0400000
#define ZNG_O_CLOEXEC    02000000
#define ZNG_O_PATH       010000000
#define ZNG_O_TMPFILE    020200000   /* __O_TMPFILE | O_DIRECTORY (asm-generic) */
#define ZNG_O_CREAT_MODE (ZNG_O_CREAT | ZNG_O_TMPFILE)  /* 这两个标志才带 mode 实参 */
/*
 * O_LARGEFILE：64 位平台上无意义（LFS 是默认），musl/glibc 都定义为 0。
 *
 * 【真机实测（华为 JDY-AN00，Android）发现的坑】照抄 asm-generic 的
 * 0100000(0x8000) 会在符号链接上触发 ELOOP —— 裸 syscall 验证：
 *     openat(AT_FDCWD, symlink路径, O_RDONLY)          -> 成功
 *     openat(AT_FDCWD, symlink路径, O_RDONLY|0x8000)   -> ELOOP
 * 普通文件不受影响，所以"cat 普通文件正常、cat 符号链接报 Too many
 * levels of symbolic links"这种诡异现象就是它。glibc 的 fopen 内部
 * 不带此标志所以 head/wc 一直正常，唯独走我们 open64 钩子的 cat 失败。
 * 结论：64 位目标上必须为 0。
 */
#define ZNG_O_LARGEFILE  0

#define ZNG_AT_FDCWD            (-100)
#define ZNG_AT_SYMLINK_NOFOLLOW 0x100
#define ZNG_AT_REMOVEDIR        0x200
#define ZNG_AT_EMPTY_PATH       0x1000
#define ZNG_AT_EACCESS          0x200

#define ZNG_RESOLVE_BENEATH 0x08
#define ZNG_RESOLVE_IN_ROOT 0x10

#define ZNG_F_OK 0
#define ZNG_X_OK 1
#define ZNG_W_OK 2
#define ZNG_R_OK 4

/* struct statx（内核布局；仅用于 statx hook 的 fstatat 回填） */
struct zng_statx {
    uint32_t mask;            /*  0 */
    uint32_t blksize;         /*  4 */
    uint64_t attributes;      /*  8 */
    uint32_t nlink;           /* 16 */
    uint32_t uid;             /* 20 */
    uint32_t gid;             /* 24 */
    uint16_t mode;            /* 28 */
    uint16_t spare0;          /* 30 */
    uint64_t ino;
    uint64_t size;
    uint64_t blocks;
    uint64_t attributes_mask;
    uint64_t atime_s;  int32_t atime_n;  int32_t pad0;
    uint64_t btime_s;  int32_t btime_n;  int32_t pad1;
    uint64_t ctime_s;  int32_t ctime_n;  int32_t pad2;
    uint64_t mtime_s;  int32_t mtime_n;  int32_t pad3;
    uint32_t rdev_major, rdev_minor;
    uint32_t dev_major,  dev_minor;
    uint64_t mnt_id;                    /* 144 */
    uint32_t dio_mem_align;             /* 152 */
    uint32_t dio_offset_align;          /* 156 */
    uint64_t subvol;                    /* 160 */
    uint32_t atomic_write_unit_min;     /* 168 —— 内核里是 **u32 min 在前**，
                                         * 不是 u64！原来这里写成 u64 max + u32 min，
                                         * 结构体直接涨到 272 字节，而调用方的缓冲只有
                                         * 256 —— statx_fill() 的 memset 一下就越界写，
                                         * 表现为 coreutils 的 ls/cat/stat 一律
                                         * "*** stack smashing detected ***"。
                                         * busybox 从不直接调 statx，所以 Alpine/Alpaquita
                                         * 上一直没暴露；Ubuntu 的 gnulib 先试 statx 就炸了。 */
    uint32_t atomic_write_unit_max;     /* 172 */
    uint32_t atomic_write_segments_max; /* 176 */
    uint32_t spare1;                    /* 180 */
    uint64_t spare3[9];                 /* 184 .. 256 */
};

/* 内核 ABI：struct statx 恰好 256 字节。少一个字段就是越界写，多一个就是读不到，
 * 所以用静态断言钉死，而不是靠人肉数偏移。 */
_Static_assert(sizeof(struct zng_statx) == 256, "struct zng_statx must be 256 bytes");

/* statx mask 位（我们能用 fstatat 回填的那些） */
#define ZNG_STATX_TYPE         0x00000001U
#define ZNG_STATX_MODE         0x00000002U
#define ZNG_STATX_NLINK        0x00000004U
#define ZNG_STATX_UID          0x00000008U
#define ZNG_STATX_GID          0x00000010U
#define ZNG_STATX_ATIME        0x00000020U
#define ZNG_STATX_MTIME        0x00000040U
#define ZNG_STATX_CTIME        0x00000080U
#define ZNG_STATX_INO          0x00000100U
#define ZNG_STATX_SIZE         0x00000200U
#define ZNG_STATX_BLOCKS       0x00000400U
#define ZNG_STATX_BASIC_STATS  0x000007ffU
#define ZNG_STATX_BTIME        0x00000800U

/* struct stat（内核 generic 布局；x86_64 与 aarch64 一致） */
/*
 * struct stat 的内核布局 **不是跨架构一致的**。
 *
 * 原来这里只写了 x86_64 的布局（dev/ino/nlink/mode...），并在注释里断言
 * "x86_64 与 aarch64 一致" —— 错的。arm64 是 mode 在前、nlink 只有 32 位：
 *
 *   x86_64: dev8 ino8 nlink8 mode4 uid4 gid4 pad4 rdev8 ...
 *   arm64 : dev8 ino8 mode4 nlink4 uid4 gid4 rdev8 pad8 ...
 *
 * 这个错误在 Alpine/Alpaquita 上完全看不出来：busybox 不直接调 statx，
 * 我们的钩子只是把调用方的 buffer 原样交给内核，根本不解释这份结构体。
 * 换成 Ubuntu（gnulib 先试 statx）后，statx_fill() 按错布局取字段，
 * 于是 `ls -l` 打出 "?rwx-wS--T ... Links: 41471"，`stat` 报 "weird file"。
 */
#if defined(__aarch64__)
struct zng_stat {
    uint64_t dev;             /*   0 */
    uint64_t ino;             /*   8 */
    uint32_t mode;            /*  16 */
    uint32_t nlink;           /*  20 */
    uint32_t uid;             /*  24 */
    uint32_t gid;             /*  28 */
    uint64_t rdev;            /*  32 */
    uint64_t pad1;            /*  40 */
    int64_t  size;            /*  48 */
    int32_t  blksize;         /*  56 */
    int32_t  pad2;            /*  60 */
    int64_t  blocks;          /*  64 */
    int64_t  atime_s, atime_n;/*  72 */
    int64_t  mtime_s, mtime_n;/*  88 */
    int64_t  ctime_s, ctime_n;/* 104 */
    uint32_t unused4, unused5;/* 120 */
};
#define ZNG_OFF_ST_UID 24
#define ZNG_OFF_ST_GID 28
#else
struct zng_stat {
    uint64_t dev;
    uint64_t ino;
    uint64_t nlink;
    uint32_t mode;
    uint32_t uid;             /* offset 28 */
    uint32_t gid;             /* offset 32 */
    uint32_t pad0;
    uint64_t rdev;
    int64_t  size;
    int64_t  blksize;
    int64_t  blocks;
    int64_t  atime_s; int64_t atime_n;
    int64_t  mtime_s; int64_t mtime_n;
    int64_t  ctime_s; int64_t ctime_n;
};
#define ZNG_OFF_ST_UID 28
#define ZNG_OFF_ST_GID 32
#endif

/*
 * arm64 的内核 struct stat 是 128 字节；用断言钉住，别再靠肉眼数偏移。
 * x86_64 那一份只是给宿主单测用的（布局 120 字节），不做断言。
 */
#if defined(__aarch64__)
_Static_assert(sizeof(struct zng_stat) == 128, "struct zng_stat must be 128 bytes");
#endif

/* ------------------------------------------------------------------ */
/* 配置（构造后只读 —— 这是线程安全的基础）                              */
/* ------------------------------------------------------------------ */

struct zng_bind {
    char  *host;        /* strdup；按需分配，避免 A 的定长 4096×2×64 */
    char  *guest;
    size_t host_len;
    size_t guest_len;
};

struct zng_cfg {
    char              root[ZNG_PATH_MAX];
    size_t            root_len;
    struct zng_bind  *binds;      /* malloc 数组 */
    int               nbinds;
    int               cap;
    int               fake_root;
    int               debug;
    int               is_glibc;   /* rootfs 是 glibc 系（影响库搜索路径，见 zng_libpath） */
    char              self[ZNG_PATH_MAX];   /* libzng.so 自身路径 */
    char              log_path[ZNG_PATH_MAX];/* ZNG_LOG：日志写文件（不污染 stderr） */
};

/* cfg 生命周期：ctor 里 build，进程存续期间只读。
 * 单元测试可直接构造一个（这就是不用全局变量换来的可测性）。 */
/* exec 前把 syscall 计数落盘并归零（见 zng_ctor.c） */
void zng_count_flush(void);

int  zng_cfg_init(struct zng_cfg *c);
void zng_cfg_free(struct zng_cfg *c);
int  zng_cfg_bind_add(struct zng_cfg *c, const char *host, const char *guest);

/* ------------------------------------------------------------------ */
/* 字符串工具（static inline：freestanding 下不产生 PLT 调用）           */
/* ------------------------------------------------------------------ */

/*
 * 长度统计保持逐字节。
 *
 * 试过 8 字节块 + haszero 的写法，快是快，但**会读过缓冲区尾部** ——
 * ASan 在单元测试里立刻报 global-buffer-overflow（字符串字面量正好卡在页尾）。
 * 翻译热路径改成"扫一遍同时算长度和规范性"（zng_scan_abs），不再单独调它。
 */
static inline size_t zng_strlen(const char *s)
{
    size_t n = 0;
    while (s && s[n]) n++;
    return n;
}

static inline int zng_memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *x = (const unsigned char *)a;
    const unsigned char *y = (const unsigned char *)b;
    while (n--) {
        if (*x != *y) return (int)*x - (int)*y;
        x++; y++;
    }
    return 0;
}

/*
 * 8 字节整字搬运（写侧对齐，读侧允许非对齐 —— x86_64 / aarch64 都支持）。
 * 建这个 shim 的目的之一是**不依赖宿主 libc**，所以不能直接调 memcpy；
 * 但字节循环在长路径上确实慢：实测 128 字符的路径，仅拷贝就要几十纳秒。
 */
static inline void *zng_memcpy(void *d, const void *s, size_t n)
{
    unsigned char *dd = (unsigned char *)d;
    const unsigned char *ss = (const unsigned char *)s;
    if (n < 16) {
        while (n--) *dd++ = *ss++;
        return d;
    }
    while (((size_t)dd & 7u) != 0) { *dd++ = *ss++; n--; }
    typedef uint64_t zng_u64a __attribute__((may_alias, aligned(1)));
    while (n >= 8) {
        *(zng_u64a *)dd = *(const zng_u64a *)ss;
        dd += 8; ss += 8; n -= 8;
    }
    while (n--) *dd++ = *ss++;
    return d;
}

static inline void *zng_memset(void *d, int v, size_t n)
{
    unsigned char *dd = (unsigned char *)d;
    while (n--) *dd++ = (unsigned char)v;
    return d;
}

static inline char *zng_strcpy(char *d, const char *s)
{
    char *r = d;
    while ((*d = *s)) { d++; s++; }
    return r;
}

/* 带长度上限的复制：成功返回写入长度（不含 NUL），不足返回 -ENAMETOOLONG。
 * 参数顺序沿用 BSD strlcpy(dst, src, size)。
 * [A] 用 snprintf(out, outn, tmp, name) 把变量当 format string —— 直接禁掉
 *     这类写法，统一走这里。 */
static inline long zng_strlcpy(char *d, const char *s, size_t dn)
{
    size_t l = zng_strlen(s);
    if (l + 1 > dn) return -ZNG_ENAMETOOLONG;
    zng_memcpy(d, s, l + 1);
    return (long)l;
}

static inline int zng_strncmp(const char *a, const char *b, size_t n)
{
    while (n && *a && *a == *b) { a++; b++; n--; }
    if (n == 0) return 0;
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

/* "KEY=" 前缀匹配：命中返回 '=' 后的偏移，否则 0 */
static inline size_t zng_envkey(const char *e, const char *key)
{
    size_t kl = zng_strlen(key);
    if (zng_strncmp(e, key, kl) == 0 && e[kl] == '=') return kl + 1;
    return 0;
}

static inline const char *zng_strchr(const char *s, int c)
{
    for (; s && *s; s++)
        if (*s == (char)c) return s;
    return (const char *)0;
}

static inline const char *zng_strrchr(const char *s, int c)
{
    const char *last = (const char *)0;
    for (; s && *s; s++)
        if (*s == (char)c) last = s;
    return last;
}

/* ------------------------------------------------------------------ */
/* errno（weak：宿主 libc 不提供时安全退化，不崩溃）                     */
/* ------------------------------------------------------------------ */

__attribute__((weak)) int *__errno_location(void);

static inline void zng_set_errno(int e)
{
    /* [A] 直接 *__errno_location() = e —— 符号缺失即 NULL 解引用崩溃 */
    if (__errno_location) *__errno_location() = e;
}

static inline int zng_get_errno(void)
{
    return __errno_location ? *__errno_location() : 0;
}

/* 原始 syscall 返回值 -> libc 约定（-1 + errno） */
static inline int zng_ret(long r)
{
    if (r < 0 && r > -4096) {
        zng_set_errno((int)-r);
        return -1;
    }
    return (int)r;
}

/* kernel -> 内部约定：成功返回 0/r，失败返回 -errno。避免使用 -1。 */
static inline long zng_err(long r)
{
    if (r < 0 && r > -4096) return r;   /* 已是 -errno 形式 */
    return r;
}

/* ------------------------------------------------------------------ */
/* 路径视图（pathview）：组件级切分，不做任何字符串拼接                  */
/* ------------------------------------------------------------------ */

struct zng_pv {
    const char *s;                  /* 源串（不复制，只读） */
    size_t      off[ZNG_MAX_COMPS];
    size_t      len[ZNG_MAX_COMPS];
    int         n;
};

/* 切分绝对路径：跳过空组件与 "."，**保留 ".."**（留给内核/解析引擎处理）。
 * 组件数超限返回 -ENAMETOOLONG。 */
int zng_pv_from(const char *p, struct zng_pv *v);
int zng_pv_is_dotdot(const struct zng_pv *v, int k);
/* 弹出 ".."（栈式），生成 cleaned 视图 */
int zng_pv_clean(const struct zng_pv *src, struct zng_pv *dst);
/* 从 from 组件起，是否匹配 prefix（prefix 可以是 "/"，匹配一切） */
int zng_pv_prefix(const struct zng_pv *v, int from, const char *prefix);
/* prefix 的组件数 */
int zng_prefix_comps(const char *prefix);
/* 把 v[from..to) 追加到 out（每个组件前加 '/'） */
int zng_pv_emit(char *out, size_t outn, size_t *olen,
                const struct zng_pv *v, int from, int to);

/* ------------------------------------------------------------------ */
/* 路径翻译（纯逻辑，完全可单测）                                        */
/* ------------------------------------------------------------------ */

/* guest -> host。
 * 返回： 0 = 未改写（已是 host 视图 / 相对路径），out 内为原路径
 *        1 = 已改写，out 内为 host 路径
 *       <0 = -errno（含 -ENAMETOOLONG；**绝不静默 passthrough**） */
int zng_translate(const struct zng_cfg *c, const char *in, char *out, size_t outn);

/* host -> guest（readlink / getcwd / /proc/self/exe 修复用）。
 * 返回： 0 = 不在沙箱内，out 内为原路径
 *        1 = 已转换，out 内为 guest 路径
 *       <0 = -errno */
int zng_untranslate(const struct zng_cfg *c, const char *host, char *out, size_t outn);

/* host 路径是否在 rootfs 内（组件边界比对，不是字符串前缀） */
int zng_under_root(const struct zng_cfg *c, const char *host);

/* ------------------------------------------------------------------ */
/* ELF 解析（纯 buffer，可单测）                                        */
/* ------------------------------------------------------------------ */

/* 给至少 64 字节的 ELF header，返回"还需读入多少字节才能覆盖 phdr 表"。
 * 返回：>0 需要读入的总字节数；ZNG_NOT_ELF；<0 = -errno */
long zng_elf_span(const unsigned char *hdr, size_t have);

/* 给完整 buffer（>= zng_elf_span 返回值），解析 PT_INTERP。
 * 返回：ZNG_ELF_DYNAMIC（interp 已填） / ZNG_ELF_STATIC / ZNG_NOT_ELF / -errno
 *
 * 注意：仅当 buffer 覆盖到 PT_INTERP 的**数据区**时才可用。
 * 实际 ELF 里 PT_INTERP 的 p_offset 通常在 phdr 表之后，而 zng_elf_span()
 * 只算到 phdr 表结尾 —— 因此执行路径请使用 zng_elf_interp_loc()。
 */
int zng_elf_interp(const unsigned char *b, size_t n, char *interp, size_t isz);

/*
 * 只从 phdr 表里取出 PT_INTERP 的**位置**（文件偏移 + 长度），不读取其内容。
 * 返回 ZNG_ELF_DYNAMIC（out_off / out_sz 已填）/ ZNG_ELF_STATIC / -errno。
 *
 * 为什么需要它（真机实测的教训）：
 *   读整个 span 再解析是不够的 —— PT_INTERP 的 p_offset 往往在 phdr 表之后，
 *   于是 zng_elf_interp() 会因 "off + fsz > n" 返回 -EIO，表现为**所有外部
 *   命令一律 I/O error**（内建命令正常），极易误判为文件系统故障。
 *   分成"定位 + 定点读取"两步后，只需多一次 lseek+read，且不受文件布局影响。
 */
int zng_elf_interp_loc(const unsigned char *b, size_t n,
                       uint64_t *off, uint64_t *sz);

/* ------------------------------------------------------------------ */
/* exec 计划（argv/env 构造 —— 纯逻辑，可单测）                          */
/* ------------------------------------------------------------------ */

struct zng_plan {
    char **argv;
    char **envp;
    int    ld_kind;
};

/* 构造"经加载器启动 prog_host"的计划。
 * interp_host 为 NULL 时按 musl 协议（ldso PROG ...）。
 * 返回的 argv/envp 由 zng_plan_free 释放 —— [A] 只 free(nargv) 漏了 nenv。 */
int  zng_plan_build(const struct zng_cfg *c,
                    const char *prog_host, const char *interp_host,
                    char *const argv[], char *const envp[],
                    struct zng_plan *out);
void zng_plan_free(struct zng_plan *p);

/* 单独构造 env（fixenv）。
 * [B] 对 envp==NULL 的特判分支返回未构造的 BSS 空串 -> LD_PRELOAD="" -> SIGSYS。
 *     这里 NULL 一律归一化为"空数组"，无条件走同一条构造路径。 */
char **zng_env_build(const struct zng_cfg *c, char *const envp[]);
void   zng_env_free(char **env);

/* ------------------------------------------------------------------ */
/* 日志（fail-visible 的载体）                                          */
/* ------------------------------------------------------------------ */

void zng_log_init(const struct zng_cfg *c);
void zng_log(const char *s);
void zng_log2(const char *a, const char *b);
void zng_logn(long v);

/* ------------------------------------------------------------------ */
/* 解析与执行（依赖 syscall 层，见 zng_sys.h）                           */
/* ------------------------------------------------------------------ */

struct zng_cfg *zng_cfg(void);          /* ctor 构建好的只读配置；未就绪返回 NULL */

/* 一次性探测 openat2 并打开 rootfd；必须在任何 hook 生效前调用 */
void zng_resolver_init(const struct zng_cfg *c);

/* 分配器：核心逻辑统一走这两个入口，便于测试替换与统计 */
void *zng_alloc_bytes(unsigned long n);
void  zng_free_bytes(void *p);

/* guest 路径 -> 已解析的 host 路径（符号链接安全）。
 * 返回 0（out 可用，AT_FDCWD 语义）/ 1（原样透传，用原始 dirfd+path）/ -errno */
int zng_resolve(const struct zng_cfg *c, const char *path, int dirfd,
                char *out, size_t outn);

/* 打开的 guest 路径 fd；返回 fd 或 -errno */
int zng_open_guest(const struct zng_cfg *c, const char *path, int dirfd,
                   long flags, long mode);

/* 执行：内部完成 ELF 探测 -> 解析解释器 -> 构造计划 -> execve。
 * 只在失败时返回。返回 -errno；ZNG_ELF_STATIC 以 -ENOSYS 表达（v1 不支持）。 */
int zng_exec_core(const struct zng_cfg *c, const char *path,
                  char *const argv[], char *const envp[], int do_search);

/* PATH 搜索（guest 视图） */
int zng_execvp(const struct zng_cfg *c, const char *file,
               char *const argv[], char *const envp[]);

#endif /* ZNG_H */
