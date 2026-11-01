/* SPDX-License-Identifier: MIT */
/*
 * zng_hooks.c — libc 钩子
 *
 * 本文件是唯一需要处理"Android 平台策略"的地方。核心是三条对策，
 * 每一条都对应 zroot-lab 用真机 7 个版本才定位到的问题：
 *
 *   [对策 1] 凭证类 syscall 家族：无条件 return 0，绝不触内核。
 *            Android app seccomp 对 setuid/setgid 家族是**显式 BLOCKLIST**
 *            （调用即 SIGSYS，不是权限不足）。busybox 的 FEATURE_SUID 启动
 *            路径会调 setgid()+setuid()，一调用就死（zroot-lab 0.1.5）。
 *            注意：这与 fake_root 无关 —— 即使不伪造 root，也必须拦下，
 *            因为 SIGSYS 无法在用户态捕获。[A] 的实现挂在 fake_root 条件
 *            下，在 Android 上是错的。
 *
 *   [对策 2] statx(291) 不发 syscall，用 fstatat 回填。
 *            [B] 的做法是让 statx 钩子直接返回 ENOSYS，把"回退"甩给调用方
 *            —— 调用方未必有回退路径，于是功能静默缺失。
 *            这里把 struct stat 完整转换成 struct statx，功能不丢失，
 *            且完全避开 291 号。
 *
 *   [对策 3] faccessat2(439) 降级到 faccessat(48)。
 *            参数布局一致，48 号在白名单内。
 */
#include "zng.h"
#include "zng_sys.h"
#include <stdarg.h>

#define ZEXPORT __attribute__((visibility("default")))

/* 转发的原函数（dlsym 解析；这些名字我们都不 hook，无递归风险） */
extern void *dlsym(void *, const char *);
#define ZNG_RTLD_NEXT ((void *)-1L)
static void *zng_fwd(const char *n) { return dlsym(ZNG_RTLD_NEXT, n); }

static int zng_fail(long r)
{
    if (zng_iserr(r)) { zng_set_errno((int)-r); return -1; }
    return (int)r;
}

/* ================================================================== */
/* statx：用 fstatat 回填（对策 2）                                     */
/* ================================================================== */

static void statx_fill(struct zng_statx *x, const struct zng_stat *st, unsigned mask)
{
    unsigned got = 0;
    zng_memset(x, 0, sizeof *x);

    if (mask & (ZNG_STATX_TYPE | ZNG_STATX_MODE)) {
        x->mode = (uint16_t)st->mode;
        got |= (mask & (ZNG_STATX_TYPE | ZNG_STATX_MODE));
    }
    if (mask & ZNG_STATX_NLINK) { x->nlink = (uint32_t)st->nlink; got |= ZNG_STATX_NLINK; }
    if (mask & ZNG_STATX_UID)   { x->uid   = st->uid;             got |= ZNG_STATX_UID; }
    if (mask & ZNG_STATX_GID)   { x->gid   = st->gid;             got |= ZNG_STATX_GID; }
    if (mask & ZNG_STATX_INO)   { x->ino   = st->ino;             got |= ZNG_STATX_INO; }
    if (mask & ZNG_STATX_SIZE)  { x->size  = (uint64_t)st->size;  got |= ZNG_STATX_SIZE; }
    if (mask & ZNG_STATX_BLOCKS){ x->blocks= (uint64_t)st->blocks;got |= ZNG_STATX_BLOCKS; }
    x->blksize = (uint32_t)st->blksize;
    x->dev_major = (uint32_t)(st->dev >> 8);
    x->dev_minor = (uint32_t)(st->dev & 0xff);
    x->rdev_major = (uint32_t)(st->rdev >> 8);
    x->rdev_minor = (uint32_t)(st->rdev & 0xff);
    if (mask & ZNG_STATX_ATIME) { x->atime_s = (uint64_t)st->atime_s; x->atime_n = (int32_t)st->atime_n; got |= ZNG_STATX_ATIME; }
    if (mask & ZNG_STATX_MTIME) { x->mtime_s = (uint64_t)st->mtime_s; x->mtime_n = (int32_t)st->mtime_n; got |= ZNG_STATX_MTIME; }
    if (mask & ZNG_STATX_CTIME) { x->ctime_s = (uint64_t)st->ctime_s; x->ctime_n = (int32_t)st->ctime_n; got |= ZNG_STATX_CTIME; }
    /* btime / attributes / mnt_id 无法从 stat 取得 —— 不置位，调用方可见 */

    x->mask = got;
}

ZEXPORT int statx(int dirfd, const char *path, int flags,
                  unsigned int mask, struct zng_statx *buf)
{
    struct zng_stat st;
    struct zng_cfg *c = zng_cfg();
    long r;

    if (!buf) { zng_set_errno(ZNG_EFAULT); return -1; }
    if (!c) {                                   /* 惰性：走原实现 */
        static int (*real)(int, const char *, int, unsigned, void *) = 0;
        if (!real) *(void **)&real = zng_fwd("statx");
        if (!real) { zng_set_errno(ZNG_ENOSYS); return -1; }
        return real(dirfd, path, flags, mask, (void *)buf);
    }

    if (path && path[0]) {
        char host[ZNG_PATH_MAX];
        int rr = zng_resolve(c, path, dirfd, host, sizeof host);
        if (rr < 0) { zng_set_errno(-rr); return -1; }
        int dfd = (rr == 0) ? ZNG_AT_FDCWD : dirfd;
        const char *p = (rr == 0) ? host : path;
        r = zng_fstatat(dfd, p, &st,
                        (flags & ZNG_AT_SYMLINK_NOFOLLOW) ? ZNG_AT_SYMLINK_NOFOLLOW : 0);
    } else {
        /* AT_EMPTY_PATH：对 dirfd 本身取样 */
        r = zng_fstat(dirfd, &st);
    }
    if (zng_iserr(r)) { zng_set_errno((int)-r); return -1; }

    if (c->fake_root) {                          /* proot -0 语义 */
        unsigned char *b = (unsigned char *)&st;
        zng_memset(b + ZNG_OFF_ST_UID, 0, 4);
        zng_memset(b + ZNG_OFF_ST_GID, 0, 4);
    }

    statx_fill(buf, &st, mask);
    return 0;
}

/* ================================================================== */
/* 打开 / 状态                                                         */
/* ================================================================== */

/* 前向声明：open/open64 复用 openat。变参函数必须先声明后使用 ——
 * 否则 C 会隐式声明成 int()，随后与变参定义冲突（编译期即报错）。 */
int openat(int dirfd, const char *path, int flags, ...);
int open(const char *path, int flags, ...);

/*
 * open / openat 的第三个实参 mode **仅在** flags 含 O_CREAT 或 O_TMPFILE 时
 * 才存在。无条件 va_arg 会读到栈上的垃圾值（未定义行为）。
 *
 * 【真机实测的 bug】原实现无条件读取 mode，于是 O_RDONLY 的普通打开
 * （cat、读文件）也带着垃圾 mode 传给 openat2；而内核规定
 *   非 (O_CREAT|O_TMPFILE) 时 how.mode 必须为 0，否则返回 -EINVAL
 * 表现为：写文件成功（带 O_CREAT，mode 恰好被正确读到），
 *         读文件一律 "Invalid argument" —— 极具迷惑性。
 */
ZEXPORT int open(const char *path, int flags, ...)
{
    long mode = 0;
    if (flags & ZNG_O_CREAT_MODE) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    return openat(ZNG_AT_FDCWD, path, flags, mode);
}

ZEXPORT int open64(const char *path, int flags, ...)
{
    long mode = 0;
    if (flags & ZNG_O_CREAT_MODE) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    return openat(ZNG_AT_FDCWD, path, flags | ZNG_O_LARGEFILE, mode);
}

ZEXPORT int openat(int dirfd, const char *path, int flags, ...)
{
    long mode = 0;
    if (flags & ZNG_O_CREAT_MODE) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }

    struct zng_cfg *c = zng_cfg();
    if (!c || !path) return zng_fail(zng_openat(dirfd, path, flags, mode));
    return zng_fail(zng_open_guest(c, path, dirfd, flags, mode));
}

/*
 * glibc 的 openat64 与 fortified 变体（_FORTIFY_SOURCE 时编译器把
 * open/openat 重定向到 __*_2）。
 *
 * 【真机实测（Alpaquita glibc）发现的 bug】busybox 的 cat 走的是
 * __open64_2 —— LD_DEBUG=symbols 显示查找顺序为
 *     busybox -> libzng.so(没有) -> ... -> libc.so.6
 * 于是落到 glibc 原实现，路径不翻译，读 /etc/os-release
 * 直接打到 Android 的 /etc，报 ELOOP。musl 无此变体，所以
 * 同一 shim 在 Alpine 下一直正常 —— bug 只在 glibc rootfs 下显形。
 *
 * 这些变体只传 flags 不传 mode（fortified 层禁止 O_CREAT 无 mode），
 * 转调各自的普通版本即可。
 */
ZEXPORT int openat64(int dirfd, const char *path, int flags, ...)
{
    long mode = 0;
    if (flags & ZNG_O_CREAT_MODE) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    return openat(dirfd, path, flags | ZNG_O_LARGEFILE, mode);
}
ZEXPORT int __open_2(const char *path, int flags)   { return open(path, flags); }
ZEXPORT int __open64_2(const char *path, int flags) { return open64(path, flags); }
ZEXPORT int __openat_2(int dirfd, const char *path, int flags)
{ return openat(dirfd, path, flags); }
ZEXPORT int __openat64_2(int dirfd, const char *path, int flags)
{ return openat64(dirfd, path, flags); }

ZEXPORT int close(int fd) { return zng_fail(zng_close(fd)); }

/*
 * 通用 syscall() 拦截：给"被 seccomp 拦、但调用点不在 libc 里"的号码兜底。
 *
 * 来历：PyTorch 在 App 里启动时死在 si_syscall=235（mbind）。
 * mbind 是 NUMA 相关调用，Android 的 app seccomp 直接拦；而 OpenBLAS
 * 是通过 glibc 的通用 syscall() 发的（号码在寄存器里，不是 movz 立即数），
 * 所以 patch-glibc-syscalls.py 的码型扫描抓不到，只能在 syscall() 这一层拦。
 *
 * 语义：返回 -1/ENOSYS，让调用方按"内核不支持"走降级路径（OpenBLAS 会
 * 关闭 NUMA 优化继续跑）。其余号码原样转发。
 */
static int zng_sc_blocked(long nr)
{
    switch (nr) {
    case 235:   /* mbind */
    case 236:   /* get_mempolicy */
    case 237:   /* set_mempolicy */
    case 238:   /* migrate_pages */
    case 239:   /* move_pages */
        return 1;
    default:
        return 0;
    }
}

ZEXPORT long syscall(long nr, ...)
{
    va_list ap;
    va_start(ap, nr);
    long a1 = va_arg(ap, long);
    long a2 = va_arg(ap, long);
    long a3 = va_arg(ap, long);
    long a4 = va_arg(ap, long);
    long a5 = va_arg(ap, long);
    long a6 = va_arg(ap, long);
    va_end(ap);

    if (zng_sc_blocked(nr)) {
        zng_set_errno(ZNG_ENOSYS);
        return -1;
    }
    return zng_sys6(nr, a1, a2, a3, a4, a5, a6);
}

/* 状态类：统一经 zng_resolve 拿 host 路径后 fstatat */
static int stat_at(const struct zng_cfg *c, int dirfd, const char *path,
                   void *buf, int nofollow)
{
    char host[ZNG_PATH_MAX];
    int r = zng_resolve(c, path, dirfd, host, sizeof host);
    if (r < 0) return -1;
    int dfd = (r == 0) ? ZNG_AT_FDCWD : dirfd;
    const char *p = (r == 0) ? host : path;
    long rr = zng_fstatat(dfd, p, (struct zng_stat *)buf,
                          nofollow ? ZNG_AT_SYMLINK_NOFOLLOW : 0);
    if (zng_iserr(rr)) { zng_set_errno((int)-rr); return -1; }
    if (c->fake_root) {
        unsigned char *b = (unsigned char *)buf;
        zng_memset(b + ZNG_OFF_ST_UID, 0, 4);
        zng_memset(b + ZNG_OFF_ST_GID, 0, 4);
    }
    return 0;
}

ZEXPORT int fstatat(int dirfd, const char *path, void *buf, int flags)
{
    struct zng_cfg *c = zng_cfg();
    if (!c || !path) return zng_fail(zng_fstatat(dirfd, path, (struct zng_stat *)buf, flags));
    return stat_at(c, dirfd, path, buf, (flags & ZNG_AT_SYMLINK_NOFOLLOW) != 0);
}
ZEXPORT int __fxstatat(int v, int d, const char *p, void *b, int f)
{ (void)v; return fstatat(d, p, b, f); }
/* glibc 的 *64 xstat 变体：64 位平台上结构布局相同，直接转调。 */
ZEXPORT int __fxstatat64(int v, int d, const char *p, void *b, int f)
{ (void)v; return fstatat(d, p, b, f); }

ZEXPORT int stat(const char *path, void *buf)
{ struct zng_cfg *c = zng_cfg();
  return (c && path) ? stat_at(c, ZNG_AT_FDCWD, path, buf, 0)
                     : zng_fail(zng_fstatat(ZNG_AT_FDCWD, path, (struct zng_stat *)buf, 0)); }
ZEXPORT int stat64(const char *path, void *buf) { return stat(path, buf); }
ZEXPORT int __xstat(int v, const char *p, void *b) { (void)v; return stat(p, b); }
ZEXPORT int __xstat64(int v, const char *p, void *b) { (void)v; return stat(p, b); }

ZEXPORT int lstat(const char *path, void *buf)
{ struct zng_cfg *c = zng_cfg();
  return (c && path) ? stat_at(c, ZNG_AT_FDCWD, path, buf, 1)
                     : zng_fail(zng_fstatat(ZNG_AT_FDCWD, path, (struct zng_stat *)buf,
                                            ZNG_AT_SYMLINK_NOFOLLOW)); }
ZEXPORT int lstat64(const char *path, void *buf) { return lstat(path, buf); }
ZEXPORT int __lxstat(int v, const char *p, void *b) { (void)v; return lstat(p, b); }
ZEXPORT int __lxstat64(int v, const char *p, void *b) { (void)v; return lstat(p, b); }

/* ---- access（对策 3） ---- */
static int access_at(const struct zng_cfg *c, int dirfd, const char *path,
                     int mode, int flags)
{
    char host[ZNG_PATH_MAX];
    int r = zng_resolve(c, path, dirfd, host, sizeof host);
    if (r < 0) { zng_set_errno(-r); return -1; }
    int dfd = (r == 0) ? ZNG_AT_FDCWD : dirfd;
    const char *p = (r == 0) ? host : path;
    /* 只保留 faccessat 支持的标志位 */
    return zng_fail(zng_faccessat(dfd, p, mode, flags & ZNG_AT_SYMLINK_NOFOLLOW));
}

ZEXPORT int faccessat(int dirfd, const char *path, int mode, int flags)
{
    struct zng_cfg *c = zng_cfg();
    if (!c || !path) return zng_fail(zng_faccessat(dirfd, path, mode, flags));
    return access_at(c, dirfd, path, mode, flags);
}

/* 对策 3：439 -> 48。AT_EACCESS / AT_EMPTY_PATH 在 48 上不支持，只能丢掉 ——
 * 这会让带这些标志的调用语义略有偏差，但比 SIGSYS 好得多。 */
ZEXPORT int faccessat2(int dirfd, const char *path, int mode, int flags)
{ return faccessat(dirfd, path, mode, flags); }

ZEXPORT int access(const char *path, int mode)
{ struct zng_cfg *c = zng_cfg();
  return (c && path) ? access_at(c, ZNG_AT_FDCWD, path, mode, 0)
                     : zng_fail(zng_faccessat(ZNG_AT_FDCWD, path, mode, 0)); }
ZEXPORT int euidaccess(const char *path, int mode)
{ struct zng_cfg *c = zng_cfg();
  return (c && path) ? access_at(c, ZNG_AT_FDCWD, path, mode, ZNG_AT_EACCESS)
                     : zng_fail(zng_faccessat(ZNG_AT_FDCWD, path, mode, ZNG_AT_EACCESS)); }
ZEXPORT int eaccess(const char *path, int mode) { return euidaccess(path, mode); }

/* ================================================================== */
/* readlink（含 /proc/self/exe 修复 —— 门禁二）                         */
/* ================================================================== */

/*
 * readlink 结果若是 rootfs 内的路径，必须转回 guest 视图，
 * 否则 /proc/self/exe 会泄漏 /data/data/... 真实路径。
 * [B] 做对了这件事（0.1.x 的 gate2）；[A] 只在 fake_root 下处理。
 */
static long readlink_impl(const struct zng_cfg *c, int dirfd, const char *path,
                          char *buf, size_t sz)
{
    char host[ZNG_PATH_MAX];
    int r = zng_resolve(c, path, dirfd, host, sizeof host);
    int dfd = (r == 0) ? ZNG_AT_FDCWD : dirfd;
    const char *p;
    if (r < 0) {
        /* 解析失败：仍尝试原路径（可能是 /proc/self/exe 这类特殊文件） */
        if (r != -ZNG_ENOENT && r != -ZNG_ENOTDIR) { zng_set_errno(-r); return -1; }
        p = path;
    } else {
        p = (r == 0) ? host : path;
    }

    char tmp[ZNG_PATH_MAX];
    size_t want = sz < sizeof tmp - 1 ? sz : sizeof tmp - 1;
    long n = zng_readlinkat(dfd, p, tmp, want);
    if (zng_iserr(n)) { zng_set_errno((int)-n); return -1; }
    tmp[n] = 0;

    if (tmp[0] == '/' && zng_under_root(c, tmp)) {
        char guest[ZNG_PATH_MAX];
        if (zng_untranslate(c, tmp, guest, sizeof guest) == 1) {
            size_t gl = zng_strlen(guest);
            if (gl > sz) gl = sz;                  /* 内核语义：截断不报错 */
            zng_memcpy(buf, guest, gl);
            return (long)gl;
        }
    }
    if ((size_t)n > sz) n = (long)sz;
    zng_memcpy(buf, tmp, (size_t)n);
    return n;
}

ZEXPORT long readlinkat(int dirfd, const char *path, char *buf, size_t sz)
{
    struct zng_cfg *c = zng_cfg();
    if (!c || !path || !buf) return zng_fail(zng_readlinkat(dirfd, path, buf, sz));
    return readlink_impl(c, dirfd, path, buf, sz);
}
ZEXPORT long readlink(const char *path, char *buf, size_t sz)
{ return readlinkat(ZNG_AT_FDCWD, path, buf, sz); }

/*
 * fortified 变体：Debian/Ubuntu 的 coreutils 用 _FORTIFY_SOURCE 编译，
 * readlink 被重定向到 __readlink_chk / __readlinkat_chk。这两个符号由
 * glibc 内部实现（直接发 syscall，不走 PLT），我们不导出就落回原实现，
 * 路径不翻译 —— `ls -l /` 于是把 /bin 的目标打印成宿主机的 "/system/bin"。
 *
 * 同一个坑在 glibc rootfs 上已经出现过一次（__open64_2，见
 * docs/device-verification.md 第 10 条）：fortified 变体必须逐个补导出。
 */
ZEXPORT long __readlink_chk(const char *path, char *buf, size_t sz, size_t buflen)
{
    (void)buflen;                       /* 调用方已保证 sz <= buflen */
    return readlink(path, buf, sz);
}
ZEXPORT long __readlinkat_chk(int dirfd, const char *path, char *buf,
                              size_t sz, size_t buflen)
{
    (void)buflen;
    return readlinkat(dirfd, path, buf, sz);
}

/* ================================================================== */
/* 叶子操作（unlink / mkdir / rename / link / ... ）                    */
/* ================================================================== */

/*
 * 整路径解析：用于"最终组件必须存在"的操作（stat / unlink / chmod ...）。
 * 成功时 *out_dfd + out_path 可直接交给 *at 系列 syscall。
 */
static int resolve_full(const struct zng_cfg *c, const char *path, int dirfd,
                        int *out_dfd, char *out_path, size_t outn)
{
    int r = zng_resolve(c, path, dirfd, out_path, outn);
    if (r < 0) { zng_set_errno(-r); return -1; }
    if (r == 1) {                       /* 透传：沿用原 dirfd + 原路径 */
        if (zng_strlcpy(out_path, path, outn) < 0) {
            zng_set_errno(ZNG_ENAMETOOLONG);
            return -1;
        }
        *out_dfd = dirfd;
    } else {
        *out_dfd = ZNG_AT_FDCWD;        /* out_path 已是 host 绝对路径 */
    }
    return 0;
}

/*
 * parent + leaf 拆分：用于"最终组件可能不存在"的操作（mkdir / creat /
 * symlink / mknod / link / rename）。
 *
 * dpath 缓冲由调用方提供（栈上）—— [B] 在这里用静态缓冲池，多线程下
 * 第 25 次调用会覆盖第 1 次的内容。
 * 调用方必须在用完后 close(*pfd)。
 */
static int split_parent(const struct zng_cfg *c, const char *path, int dirfd,
                        char *dpath, size_t dpathn, int *pfd, const char **leaf)
{
    const char *slash = zng_strrchr(path, '/');
    if (!slash) {                       /* 无斜杠：父就是 dirfd/cwd 本身 */
        *pfd = dirfd;
        *leaf = path;
        return 0;
    }

    size_t dl = (size_t)(slash - path);
    if (dl == 0) dl = 1;                /* "/x" 的父是 "/" */
    if (dl >= dpathn) return -ZNG_ENAMETOOLONG;
    zng_memcpy(dpath, path, dl);
    dpath[dl] = 0;

    char host[ZNG_PATH_MAX];
    int r = zng_resolve(c, dpath, dirfd, host, sizeof host);
    if (r < 0) return r;

    int fd = (int)zng_openat(ZNG_AT_FDCWD, (r == 0) ? host : dpath,
                             ZNG_O_PATH | ZNG_O_DIRECTORY | ZNG_O_CLOEXEC, 0);
    if (zng_iserr(fd)) return (int)fd;
    *pfd = fd;
    *leaf = slash + 1;
    /*
     * 路径以 '/' 结尾（或就是 "/"）时 leaf 会是空串。
     * 拿空串去调 *at() 只会得到 ENOENT，语义也不对 ——
     * 目标是**目录本身**，应当用 "." 表达。
     *
     * 【真机实测的 bug】busybox 的 `mkdir -p` 是逐级创建的，会先
     * mkdir("/")；修复前这里传空串，于是报
     *   mkdir: can't create directory '/': No such file or directory
     * 连带让所有 `mkdir -p` 场景（含管道测试里的 tar 用例）一起失败。
     * 用 "." 之后，mkdir("/") 正确地返回 EEXIST，busybox 会继续下一级。
     */
    if (**leaf == 0) *leaf = ".";
    return 0;
}

/* 宏：借用父 fd 执行一个 *at 操作，并保证 fd 一定被关闭 */
#define WITH_PARENT(c, path, dirfd, leaf, body)                             \
    do {                                                                    \
        char dp_[ZNG_PATH_MAX];                                             \
        int pfd_ = ZNG_AT_FDCWD;                                            \
        const char *leaf_ = (path);                                         \
        int spr_ = split_parent((c), (path), (dirfd), dp_, sizeof dp_,      \
                                &pfd_, &leaf_);                             \
        if (spr_ < 0) { zng_set_errno(-spr_); return -1; }                  \
        { const char *leaf = leaf_; const int pfd = pfd_; body; }           \
        if (pfd_ != (dirfd) && pfd_ != ZNG_AT_FDCWD) zng_close(pfd_);       \
    } while (0)

/* ---- 删除 / 目录 ---- */
ZEXPORT int unlinkat(int dirfd, const char *path, int flags)
{
    struct zng_cfg *c = zng_cfg();
    if (!c || !path) return zng_fail(zng_unlinkat(dirfd, path, flags));
    char h[ZNG_PATH_MAX];
    int dfd;
    if (resolve_full(c, path, dirfd, &dfd, h, sizeof h) < 0) return -1;
    return zng_fail(zng_unlinkat(dfd, h, flags));
}
ZEXPORT int unlink(const char *path) { return unlinkat(ZNG_AT_FDCWD, path, 0); }
ZEXPORT int rmdir(const char *path)  { return unlinkat(ZNG_AT_FDCWD, path, ZNG_AT_REMOVEDIR); }

/* ---- 创建（最终组件不存在，走 parent） ---- */
ZEXPORT int mkdirat(int dirfd, const char *path, unsigned int mode)
{
    struct zng_cfg *c = zng_cfg();
    if (!c || !path) return zng_fail(zng_mkdirat(dirfd, path, mode));
    WITH_PARENT(c, path, dirfd, leaf,
                return zng_fail(zng_mkdirat(pfd, leaf, mode)););
}
ZEXPORT int mkdir(const char *path, unsigned int mode)
{ return mkdirat(ZNG_AT_FDCWD, path, mode); }

ZEXPORT int mknodat(int dirfd, const char *path, unsigned int mode, unsigned long dev)
{
    struct zng_cfg *c = zng_cfg();
    if (!c || !path) return zng_fail(zng_mknodat(dirfd, path, mode, dev));
    WITH_PARENT(c, path, dirfd, leaf,
                return zng_fail(zng_mknodat(pfd, leaf, mode, dev)););
}
ZEXPORT int mknod(const char *path, unsigned int mode, unsigned long dev)
{ return mknodat(ZNG_AT_FDCWD, path, mode, dev); }

/* creat：等价于 open(O_CREAT|O_WRONLY|O_TRUNC)，最终组件也不存在 */
ZEXPORT int creat(const char *path, unsigned int mode)
{
    return openat(ZNG_AT_FDCWD, path,
                  ZNG_O_WRONLY | ZNG_O_CREAT | ZNG_O_TRUNC, (long)mode);
}

/* ---- 链接 ---- */
/*
 * 符号链接的 target 由**内核**解析，不经过我们的钩子。
 * 因此绝对 target 必须先翻译成 host 路径，否则会被按真实根解析而逃出 rootfs：
 *   ln -sf /etc/os-release /tmp/rel   ->  内核去读 Android 的 /etc/os-release
 *                                         结果 No such file or directory
 *
 * 翻译成 host 路径后，内核解析指向 rootfs 内部，读取正常；
 * 而 readlink 侧已有 untranslate，调用方看到的仍是 guest 路径 —— 两端一致。
 */
ZEXPORT int symlinkat(const char *target, int newdirfd, const char *linkpath)
{
    struct zng_cfg *c = zng_cfg();
    if (!c || !linkpath) return zng_fail(zng_symlinkat(target, newdirfd, linkpath));

    char thost[ZNG_PATH_MAX];
    const char *tgt = target;
    if (target && target[0] == '/') {
        int r = zng_translate(c, target, thost, sizeof thost);
        if (r == 1) tgt = thost;          /* 已改写为 host 路径 */
        else if (r < 0) { zng_set_errno(-r); return -1; }
        /* r == 0：未改写（理论上不会发生），沿用原值 */
    }
    WITH_PARENT(c, linkpath, newdirfd, leaf,
                return zng_fail(zng_symlinkat(tgt, pfd, leaf)););
}
ZEXPORT int symlink(const char *t, const char *l)
{ return symlinkat(t, ZNG_AT_FDCWD, l); }

ZEXPORT int linkat(int od, const char *op, int nd, const char *np, int flags)
{
    struct zng_cfg *c = zng_cfg();
    if (!c || !op || !np)
        return zng_fail(zng_linkat(od, op, nd, np, flags));
    /* 两端都解析成 host 绝对路径；跨 bind 时内核会正确报 EXDEV */
    char h1[ZNG_PATH_MAX], h2[ZNG_PATH_MAX];
    int d1, d2;
    if (resolve_full(c, op, od, &d1, h1, sizeof h1) < 0) return -1;
    if (resolve_full(c, np, nd, &d2, h2, sizeof h2) < 0) return -1;
    return zng_fail(zng_linkat(d1, h1, d2, h2,
                               (flags & ~(ZNG_AT_SYMLINK_NOFOLLOW |
                                          ZNG_AT_EMPTY_PATH)) |
                               ((flags & ZNG_AT_SYMLINK_NOFOLLOW) ? ZNG_AT_SYMLINK_NOFOLLOW : 0)));
}
ZEXPORT int link(const char *o, const char *n) { return linkat(ZNG_AT_FDCWD, o, ZNG_AT_FDCWD, n, 0); }

ZEXPORT int renameat(int od, const char *op, int nd, const char *np)
{
    struct zng_cfg *c = zng_cfg();
    if (!c || !op || !np) return zng_fail(zng_renameat(od, op, nd, np));
    char h1[ZNG_PATH_MAX], h2[ZNG_PATH_MAX];
    int d1, d2;
    if (resolve_full(c, op, od, &d1, h1, sizeof h1) < 0) return -1;
    if (resolve_full(c, np, nd, &d2, h2, sizeof h2) < 0) return -1;
    return zng_fail(zng_renameat(d1, h1, d2, h2));
}
ZEXPORT int rename(const char *o, const char *n) { return renameat(ZNG_AT_FDCWD, o, ZNG_AT_FDCWD, n); }

/*
 * renameat2：coreutils 的 `mv` 在 Debian/Ubuntu 上走这条（带 RENAME_NOREPLACE）。
 * 只导出 renameat 不够 —— 没钩住的 renameat2 会带着 guest 路径直接进内核，
 * 于是 `mv /tmp/d1 /tmp/d2` 报 "No such file or directory"（宿主机上确实没有
 * /tmp/d1）。busybox 的 mv 用 rename，所以 Alpine/Alpaquita 上从没暴露。
 */
ZEXPORT int renameat2(int od, const char *op, int nd, const char *np, unsigned flags)
{
    struct zng_cfg *c = zng_cfg();
    if (!c || !op || !np) return zng_fail(zng_renameat2(od, op, nd, np, flags));
    char h1[ZNG_PATH_MAX], h2[ZNG_PATH_MAX];
    int d1, d2;
    if (resolve_full(c, op, od, &d1, h1, sizeof h1) < 0) return -1;
    if (resolve_full(c, np, nd, &d2, h2, sizeof h2) < 0) return -1;
    return zng_fail(zng_renameat2(d1, h1, d2, h2, flags));
}

/* ---- 属性 ---- */
ZEXPORT int fchmodat(int dirfd, const char *path, unsigned int mode, int flags)
{
    struct zng_cfg *c = zng_cfg();
    if (!c || !path) return zng_fail(zng_fchmodat(dirfd, path, mode, flags));
    char h[ZNG_PATH_MAX];
    int dfd;
    if (resolve_full(c, path, dirfd, &dfd, h, sizeof h) < 0) return -1;
    return zng_fail(zng_fchmodat(dfd, h, mode, flags & ZNG_AT_SYMLINK_NOFOLLOW));
}
ZEXPORT int chmod(const char *path, unsigned int mode)
{ return fchmodat(ZNG_AT_FDCWD, path, mode, 0); }

ZEXPORT int fchownat(int dirfd, const char *path, unsigned int uid,
                     unsigned int gid, int flags)
{
    struct zng_cfg *c = zng_cfg();
    if (!c || !path) return zng_fail(zng_fchownat(dirfd, path, uid, gid, flags));
    char h[ZNG_PATH_MAX];
    int dfd;
    if (resolve_full(c, path, dirfd, &dfd, h, sizeof h) < 0) return -1;
    return zng_fail(zng_fchownat(dfd, h, uid, gid, flags & ZNG_AT_SYMLINK_NOFOLLOW));
}
ZEXPORT int chown(const char *path, unsigned int u, unsigned int g)
{ return fchownat(ZNG_AT_FDCWD, path, u, g, 0); }
ZEXPORT int lchown(const char *path, unsigned int u, unsigned int g)
{ return fchownat(ZNG_AT_FDCWD, path, u, g, ZNG_AT_SYMLINK_NOFOLLOW); }

ZEXPORT int utimensat(int dirfd, const char *path, const long *ts, int flags)
{
    struct zng_cfg *c = zng_cfg();
    if (!c) return zng_fail(zng_utimensat(dirfd, path, ts, flags));
    if (!path) return zng_fail(zng_utimensat(dirfd, path, ts, flags));
    char h[ZNG_PATH_MAX];
    int dfd;
    if (resolve_full(c, path, dirfd, &dfd, h, sizeof h) < 0) return -1;
    return zng_fail(zng_utimensat(dfd, h, ts, flags & ZNG_AT_SYMLINK_NOFOLLOW));
}

ZEXPORT int truncate(const char *path, long len)
{
    struct zng_cfg *c = zng_cfg();
    if (!c || !path) return zng_fail(zng_truncate(path, len));
    char h[ZNG_PATH_MAX];
    int dfd;
    if (resolve_full(c, path, ZNG_AT_FDCWD, &dfd, h, sizeof h) < 0) return -1;
    if (dfd != ZNG_AT_FDCWD) {          /* 相对路径：走 ftruncate 不可行，报错 */
        zng_set_errno(ZNG_EINVAL);
        return -1;
    }
    return zng_fail(zng_truncate(h, len));
}

ZEXPORT int chdir(const char *path)
{
    struct zng_cfg *c = zng_cfg();
    if (!c || !path) return zng_fail(zng_chdir(path));
    char host[ZNG_PATH_MAX];
    int r = zng_resolve(c, path, ZNG_AT_FDCWD, host, sizeof host);
    if (r < 0) { zng_set_errno(-r); return -1; }
    return zng_fail(zng_chdir((r == 0) ? host : path));
}

ZEXPORT char *getcwd(char *buf, size_t size)
{
    char tmp[ZNG_PATH_MAX];
    long r = zng_getcwd(tmp, sizeof tmp);
    if (zng_iserr(r)) { zng_set_errno((int)-r); return (char *)0; }

    struct zng_cfg *c = zng_cfg();
    const char *out = tmp;
    if (c) {
        char guest[ZNG_PATH_MAX];
        if (zng_untranslate(c, tmp, guest, sizeof guest) == 1) out = guest;
    }
    size_t l = zng_strlen(out) + 1;
    if (!buf) {
        /* glibc 允许 buf==NULL 时自行分配 —— 这里保守返回 NULL+ENAMETOOLONG
         * 之前先尝试用宿主 malloc，失败才报错 */
        char *p = (char *)zng_alloc_bytes(l);
        if (!p) { zng_set_errno(ZNG_ENOMEM); return (char *)0; }
        zng_memcpy(p, out, l);
        return p;
    }
    if (l > size) { zng_set_errno(ZNG_ERANGE); return (char *)0; }
    zng_memcpy(buf, out, l);
    return buf;
}

/* ================================================================== */
/* 身份类（对策 1 —— 本文件最重要的一组）                                */
/* ================================================================== */

/*
 * Android seccomp 对凭证 syscall 家族是显式 BLOCKLIST：调用即 SIGSYS，
 * 与是否伪造 root 无关。因此这一组**无条件**返回 0 / 不触内核。
 *
 * 这不是"安全功能"，而是"平台适配"—— 它让 busybox 的 FEATURE_SUID
 * 启动路径（setgid + setuid）不至于把整个进程打死。
 */
ZEXPORT int setuid(unsigned int u)    { (void)u; return 0; }
ZEXPORT int setgid(unsigned int g)    { (void)g; return 0; }
ZEXPORT int seteuid(unsigned int u)   { (void)u; return 0; }
ZEXPORT int setegid(unsigned int g)   { (void)g; return 0; }
ZEXPORT int setreuid(unsigned int r, unsigned int e) { (void)r; (void)e; return 0; }
ZEXPORT int setregid(unsigned int r, unsigned int g) { (void)r; (void)g; return 0; }
ZEXPORT int setresuid(unsigned int r, unsigned int e, unsigned int s)
{ (void)r; (void)e; (void)s; return 0; }
ZEXPORT int setresgid(unsigned int r, unsigned int e, unsigned int s)
{ (void)r; (void)e; (void)s; return 0; }
ZEXPORT int setfsuid(unsigned int u)  { (void)u; return 0; }
ZEXPORT int setfsgid(unsigned int g)  { (void)g; return 0; }
ZEXPORT int setgroups(size_t n, const unsigned int *l) { (void)n; (void)l; return 0; }
ZEXPORT int initgroups(const char *u, unsigned int g)  { (void)u; (void)g; return 0; }

/* 查询类：默认返回真实值（它们在 allowlist 内，调用安全）。
 * 只有显式开启 fake_root 才伪造 —— 与 [A] 一致。 */
ZEXPORT unsigned int getuid(void)
{ struct zng_cfg *c = zng_cfg();
  return (c && c->fake_root) ? 0 : (unsigned int)zng_getuid(); }
ZEXPORT unsigned int geteuid(void)
{ struct zng_cfg *c = zng_cfg();
  return (c && c->fake_root) ? 0 : (unsigned int)zng_geteuid(); }
ZEXPORT unsigned int getgid(void)
{ struct zng_cfg *c = zng_cfg();
  return (c && c->fake_root) ? 0 : (unsigned int)zng_getgid(); }
ZEXPORT unsigned int getegid(void)
{ struct zng_cfg *c = zng_cfg();
  return (c && c->fake_root) ? 0 : (unsigned int)zng_getegid(); }

/* ================================================================== */
/* stdio / 目录流（转发：libc 内部 open 会绕过 PLT，只能转路径）          */
/* ================================================================== */

static const char *tr_path(const struct zng_cfg *c, const char *path,
                           char *host, size_t hostn)
{
    if (!c || !path) return path;
    int r = zng_resolve(c, path, ZNG_AT_FDCWD, host, hostn);
    if (r < 0) return path;                     /* 解析失败：用原路径，让 libc 报错 */
    return (r == 0) ? host : path;
}

ZEXPORT void *fopen(const char *path, const char *mode)
{
    static void *(*real)(const char *, const char *) = 0;
    if (!real) *(void **)&real = zng_fwd("fopen");
    if (!real) { zng_set_errno(ZNG_ENOSYS); return (void *)0; }
    struct zng_cfg *c = zng_cfg();
    char host[ZNG_PATH_MAX];
    const char *p = tr_path(c, path, host, sizeof host);
    void *r = real(p, mode);
    if (c && c->debug) { zng_log2("dbg fopen: path =", path); zng_log2("dbg fopen: real-path =", p);
        zng_log("dbg fopen: rc="); zng_logn((long)r); zng_log("\n"); }
    return r;
}
ZEXPORT void *fopen64(const char *path, const char *mode) { return fopen(path, mode); }

ZEXPORT void *freopen(const char *path, const char *mode, void *stream)
{
    static void *(*real)(const char *, const char *, void *) = 0;
    if (!real) *(void **)&real = zng_fwd("freopen");
    if (!real) { zng_set_errno(ZNG_ENOSYS); return (void *)0; }
    struct zng_cfg *c = zng_cfg();
    char host[ZNG_PATH_MAX];
    const char *p = tr_path(c, path, host, sizeof host);
    void *r = real(p, mode, stream);
    if (c && c->debug) { zng_log2("dbg freopen: path =", path); zng_log2("dbg freopen: real-path =", p);
        zng_log("dbg freopen: rc="); zng_logn((long)r); zng_log("\n"); }
    return r;
}

/*
 * 【真机实测（Alpaquita glibc）发现的 bug】busybox cat 打开文件走的是
 * freopen64 —— LD_DEBUG=bindings 显示它绑定到 libc.so.6（我们没导出），
 * 路径不翻译，open 打到 Android 真实的 /etc/os-release，报 ELOOP。
 * 表现极具迷惑性：head/wc 走 open64（我们有钩子）一切正常，
 * 同一个符号链接唯独 cat 失败。musl 无 *64 变体所以 Alpine 下从未显形。
 */
ZEXPORT void *freopen64(const char *path, const char *mode, void *stream)
{ return freopen(path, mode, stream); }

ZEXPORT void *opendir(const char *path)
{
    static void *(*real)(const char *) = 0;
    if (!real) *(void **)&real = zng_fwd("opendir");
    if (!real) { zng_set_errno(ZNG_ENOSYS); return (void *)0; }
    struct zng_cfg *c = zng_cfg();
    char host[ZNG_PATH_MAX];
    return real(tr_path(c, path, host, sizeof host));
}

/* ================================================================== */
/* exec 全家                                                           */
/* ================================================================== */

ZEXPORT int execve(const char *path, char *const argv[], char *const envp[])
{
    struct zng_cfg *c = zng_cfg();
    if (!c) {
        static int (*real)(const char *, char *const[], char *const[]) = 0;
        if (!real) *(void **)&real = zng_fwd("execve");
        if (!real) { zng_set_errno(ZNG_ENOSYS); return -1; }
        return real(path, argv, envp);
    }
    int r = zng_exec_core(c, path, argv, envp, 0);
    if (r < 0) { zng_set_errno(-r); return -1; }
    zng_set_errno(ZNG_EIO);        /* execve 成功不会返回 */
    return -1;
}

ZEXPORT int execv(const char *path, char *const argv[])
{ return execve(path, argv, environ); }

ZEXPORT int execvpe(const char *file, char *const argv[], char *const envp[])
{
    struct zng_cfg *c = zng_cfg();
    if (!c) {
        static int (*real)(const char *, char *const[], char *const[]) = 0;
        if (!real) *(void **)&real = zng_fwd("execvpe");
        if (!real) { zng_set_errno(ZNG_ENOSYS); return -1; }
        return real(file, argv, envp);
    }
    if (!file || !file[0]) { zng_set_errno(ZNG_ENOENT); return -1; }
    if (zng_strchr(file, '/')) return execve(file, argv, envp);

    /* PATH 搜索（guest 视图） */
    const char *pp = (const char *)0;
    for (char *const *e = envp; e && *e; e++)
        if (zng_envkey(*e, "PATH")) { pp = *e + 5; break; }
    if (!pp || !pp[0]) pp = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

    int last = -ZNG_ENOENT;
    char cand[ZNG_PATH_MAX];
    for (const char *p = pp; ; ) {
        const char *seg = p;
        while (*p && *p != ':') p++;
        size_t sl = (size_t)(p - seg);
        size_t cl = 0;
        if (sl) { if (sl + 1 >= sizeof cand) goto next; zng_memcpy(cand, seg, sl); cl = sl; }
        else cand[cl++] = '.';
        cand[cl++] = '/';
        size_t fl = zng_strlen(file);
        if (cl + fl + 1 > sizeof cand) goto next;
        zng_memcpy(cand + cl, file, fl + 1);

        {
            int r = zng_exec_core(c, cand, argv, envp, 0);
            if (r == -ZNG_EACCES) { last = -ZNG_EACCES; goto next; }
            if (r == -ZNG_ENOENT || r == -ZNG_ENOTDIR) goto next;
            if (r < 0) { zng_set_errno(-r); return -1; }
        }
next:
        if (!*p) break;
        p++;
    }
    zng_set_errno(-last);
    return -1;
}

ZEXPORT int execvp(const char *file, char *const argv[])
{ return execvpe(file, argv, environ); }

ZEXPORT int execl(const char *path, const char *a0, ...)
{
    va_list ap;
    int n = 0;
    char **argv;
    va_start(ap, a0);
    while (va_arg(ap, char *) != 0) n++;
    va_end(ap);
    argv = (char **)zng_alloc_bytes(sizeof(char *) * (unsigned long)(n + 2));
    if (!argv) { zng_set_errno(ZNG_ENOMEM); return -1; }
    int i = 0;
    argv[i++] = (char *)a0;
    va_start(ap, a0);
    for (int k = 0; k < n; k++) argv[i++] = va_arg(ap, char *);
    va_end(ap);
    argv[i] = (char *)0;
    int r = execve(path, argv, environ);
    zng_free_bytes(argv);
    return r;
}

ZEXPORT int execlp(const char *file, const char *a0, ...)
{
    va_list ap;
    int n = 0;
    char **argv;
    va_start(ap, a0);
    while (va_arg(ap, char *) != 0) n++;
    va_end(ap);
    argv = (char **)zng_alloc_bytes(sizeof(char *) * (unsigned long)(n + 2));
    if (!argv) { zng_set_errno(ZNG_ENOMEM); return -1; }
    int i = 0;
    argv[i++] = (char *)a0;
    va_start(ap, a0);
    for (int k = 0; k < n; k++) argv[i++] = va_arg(ap, char *);
    va_end(ap);
    argv[i] = (char *)0;
    int r = execvpe(file, argv, environ);
    zng_free_bytes(argv);
    return r;
}

ZEXPORT int execle(const char *path, const char *a0, ...)
{
    va_list ap;
    int n = 0;
    char **argv;
    char *const *envp;
    va_start(ap, a0);
    while (va_arg(ap, char *) != 0) n++;
    envp = va_arg(ap, char *const *);
    va_end(ap);
    argv = (char **)zng_alloc_bytes(sizeof(char *) * (unsigned long)(n + 2));
    if (!argv) { zng_set_errno(ZNG_ENOMEM); return -1; }
    int i = 0;
    argv[i++] = (char *)a0;
    va_start(ap, a0);
    for (int k = 0; k < n; k++) argv[i++] = va_arg(ap, char *);
    va_end(ap);
    argv[i] = (char *)0;
    int r = execve(path, argv, envp);
    zng_free_bytes(argv);
    return r;
}
