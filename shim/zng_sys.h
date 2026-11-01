/* SPDX-License-Identifier: MIT */
/*
 * zng_sys.h — 裸 syscall 层（freestanding，无 libc）
 *
 * 两条硬性规则：
 *
 *  1. 只用"确定在 Android seccomp 老白名单里"的 syscall。
 *     [B 的教训 0.1.2 / 0.1.5] Android 按 targetSdk 给 app 进程装 zygote
 *     seccomp 过滤器：musl 内嵌的 faccessat2(439) / statx(291) 不在老白名单，
 *     凭证类 syscall 更是显式 BLOCKLIST —— 一调用就是 SIGSYS（exit=159），
 *     连 ENOSYS 都拿不到，用户态**无法捕获**。
 *     => 本文件的 ZNG_NR_statx / ZNG_NR_faccessat2 / ZNG_NR_rseq 三件套
 *        仅以 *_FORBIDDEN 注释标出，shim 任何路径都不得发起它们：
 *          · statx   -> 由 fstatat 回填（zng_hooks.c）
 *          · faccessat2 -> 降级 faccessat(48)
 *          · rseq    -> 不需使用（若 rootfs libc 需要，见 tools/patch-musl.py）
 *        它们的号仍在表里，仅供 zng_probe 探测工具使用（独立进程，死了无妨）。
 *
 *  2. 双架构号表 + 测试校验。
 *     [A] zsuper.c 的 _Static_assert 只覆盖 x86_64，arm64 分支从未验证。
 *     [B] zroot.h 只有一套硬编码 arm64 号，无任何校验。
 *     => 号表集中于此；校验放进 tests/（测试程序可 include <sys/syscall.h>
 *        与 libc 常量对照，shim 本身保持 freestanding）。
 */
/*
 * syscall 计数（ZNG_COUNT=1 时开启）。
 *
 * 存在的理由：优化要能被证明。"每条 exec 从 12 个 syscall 降到 4 个"这种话，
 * 只有数出来才算数 —— 端到端计时会被 fork/exec 本身和页缓存淹没。
 * 关闭时只多一次可预测分支；开启时在进程退出（destructor）把计数写进日志。
 */
extern unsigned long zng_sc[512];
extern int zng_sc_on;
static inline void zng_tick(long n)
{
    if (zng_sc_on && (unsigned long)n < 512UL) zng_sc[(unsigned long)n]++;
}

#ifndef ZNG_SYS_H
#define ZNG_SYS_H

#include <stddef.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* syscall 号                                                          */
/* ------------------------------------------------------------------ */

#if defined(__aarch64__)

#define ZNG_NR_read            63
#define ZNG_NR_write           64
#define ZNG_NR_openat          56
#define ZNG_NR_openat2         437
#define ZNG_NR_close           57
#define ZNG_NR_lseek           62
#define ZNG_NR_newfstatat      79
#define ZNG_NR_fstat           80
#define ZNG_NR_readlinkat      78
#define ZNG_NR_faccessat       48
#define ZNG_NR_getcwd          17
#define ZNG_NR_chdir           49
#define ZNG_NR_fchdir          50
#define ZNG_NR_dup3            24
#define ZNG_NR_dup2            23
#define ZNG_NR_pipe2           59
#define ZNG_NR_getdents64      61
#define ZNG_NR_execve          221
#define ZNG_NR_exit            93
#define ZNG_NR_exit_group      94
#define ZNG_NR_unlinkat        35
#define ZNG_NR_mkdirat         34
#define ZNG_NR_mknodat         33
#define ZNG_NR_renameat        38
#define ZNG_NR_renameat2       276
#define ZNG_NR_symlinkat       36
#define ZNG_NR_linkat          37
#define ZNG_NR_fchmodat        53
#define ZNG_NR_fchownat        54
#define ZNG_NR_utimensat       88
#define ZNG_NR_truncate        45
#define ZNG_NR_ftruncate       46
#define ZNG_NR_mmap            222
#define ZNG_NR_munmap          215
#define ZNG_NR_mprotect        226
#define ZNG_NR_brk             214
#define ZNG_NR_ioctl           29
#define ZNG_NR_fcntl           25
#define ZNG_NR_prctl           167
#define ZNG_NR_getpid          172
#define ZNG_NR_getuid          174
#define ZNG_NR_geteuid         175
#define ZNG_NR_getgid          176
#define ZNG_NR_getegid         177
#define ZNG_NR_getrandom       278
#define ZNG_NR_wait4           260
#define ZNG_NR_clone           220
#define ZNG_NR_fork            220   /* arm64 无 fork，用 clone */

/* ---- 禁止 shim 调用（仅 zng_probe 可用） ---- */
#define ZNG_NR_statx_FORBIDDEN       291
#define ZNG_NR_faccessat2_FORBIDDEN  439
#define ZNG_NR_rseq_FORBIDDEN        293

#elif defined(__x86_64__)

#define ZNG_NR_read            0
#define ZNG_NR_write           1
#define ZNG_NR_openat          257
#define ZNG_NR_openat2         437
#define ZNG_NR_close           3
#define ZNG_NR_lseek           8
#define ZNG_NR_newfstatat      262
#define ZNG_NR_fstat           5
#define ZNG_NR_readlinkat      267
#define ZNG_NR_faccessat       269
#define ZNG_NR_getcwd          79
#define ZNG_NR_chdir           80
#define ZNG_NR_fchdir          81
#define ZNG_NR_dup3            292
#define ZNG_NR_dup2            33
#define ZNG_NR_pipe2           293
#define ZNG_NR_getdents64      217
#define ZNG_NR_execve          59
#define ZNG_NR_exit            60
#define ZNG_NR_exit_group      231
#define ZNG_NR_unlinkat        263
#define ZNG_NR_mkdirat         258
#define ZNG_NR_mknodat         259
#define ZNG_NR_renameat        264
#define ZNG_NR_renameat2       316
#define ZNG_NR_symlinkat       266
#define ZNG_NR_linkat          265
#define ZNG_NR_fchmodat        268
#define ZNG_NR_fchownat        260
#define ZNG_NR_utimensat       280
#define ZNG_NR_truncate        76
#define ZNG_NR_ftruncate       77
#define ZNG_NR_mmap            9
#define ZNG_NR_munmap          11
#define ZNG_NR_mprotect        10
#define ZNG_NR_brk             12
#define ZNG_NR_ioctl           16
#define ZNG_NR_fcntl           72
#define ZNG_NR_prctl           157
#define ZNG_NR_getpid          39
#define ZNG_NR_getuid          102
#define ZNG_NR_geteuid         107
#define ZNG_NR_getgid          104
#define ZNG_NR_getegid         108
#define ZNG_NR_getrandom       318
#define ZNG_NR_wait4           61
#define ZNG_NR_clone           56
#define ZNG_NR_fork            57

#define ZNG_NR_statx_FORBIDDEN       332
#define ZNG_NR_faccessat2_FORBIDDEN  439
#define ZNG_NR_rseq_FORBIDDEN        334

#else
#error "zng: unsupported architecture (only aarch64 and x86_64)"
#endif

/* ------------------------------------------------------------------ */
/* 原始 syscall 入口                                                   */
/* ------------------------------------------------------------------ */

#if defined(__aarch64__)

#define ZNG_CLOB "memory", "cc"

static inline long zng_sys0(long n)
{
    zng_tick(n);
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = 0;
    __asm__ __volatile__("svc #0" : "+r"(x0) : "r"(x8) : ZNG_CLOB);
    return x0;
}
static inline long zng_sys1(long n, long a)
{
    zng_tick(n);
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    __asm__ __volatile__("svc #0" : "+r"(x0) : "r"(x8) : ZNG_CLOB);
    return x0;
}
static inline long zng_sys2(long n, long a, long b)
{
    zng_tick(n);
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    __asm__ __volatile__("svc #0" : "+r"(x0) : "r"(x8), "r"(x1) : ZNG_CLOB);
    return x0;
}
static inline long zng_sys3(long n, long a, long b, long c)
{
    zng_tick(n);
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    __asm__ __volatile__("svc #0"
                         : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : ZNG_CLOB);
    return x0;
}
static inline long zng_sys4(long n, long a, long b, long c, long d)
{
    zng_tick(n);
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    __asm__ __volatile__("svc #0"
                         : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
                         : ZNG_CLOB);
    return x0;
}
static inline long zng_sys5(long n, long a, long b, long c, long d, long e)
{
    zng_tick(n);
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    __asm__ __volatile__("svc #0"
                         : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4)
                         : ZNG_CLOB);
    return x0;
}
static inline long zng_sys6(long n, long a, long b, long c, long d, long e, long f)
{
    zng_tick(n);
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    __asm__ __volatile__("svc #0"
                         : "+r"(x0)
                         : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                         : ZNG_CLOB);
    return x0;
}

#else /* __x86_64__ */

/* syscall 指令破坏 rcx/r11，必须声明 */
#define ZNG_CLOB "rcx", "r11", "memory", "cc"

static inline long zng_sys0(long n)
{
    zng_tick(n);
    register long rax __asm__("rax") = n;
    __asm__ __volatile__("syscall" : "+r"(rax) : : ZNG_CLOB);
    return rax;
}
static inline long zng_sys1(long n, long a)
{
    zng_tick(n);
    register long rax __asm__("rax") = n;
    __asm__ __volatile__("syscall" : "+r"(rax) : "D"(a) : ZNG_CLOB);
    return rax;
}
static inline long zng_sys2(long n, long a, long b)
{
    zng_tick(n);
    register long rax __asm__("rax") = n;
    __asm__ __volatile__("syscall" : "+r"(rax) : "D"(a), "S"(b) : ZNG_CLOB);
    return rax;
}
static inline long zng_sys3(long n, long a, long b, long c)
{
    zng_tick(n);
    register long rax __asm__("rax") = n;
    __asm__ __volatile__("syscall" : "+r"(rax) : "D"(a), "S"(b), "d"(c) : ZNG_CLOB);
    return rax;
}
static inline long zng_sys4(long n, long a, long b, long c, long d)
{
    zng_tick(n);
    register long rax __asm__("rax") = n;
    register long r10 __asm__("r10") = d;
    __asm__ __volatile__("syscall" : "+r"(rax)
                         : "D"(a), "S"(b), "d"(c), "r"(r10) : ZNG_CLOB);
    return rax;
}
static inline long zng_sys5(long n, long a, long b, long c, long d, long e)
{
    zng_tick(n);
    register long rax __asm__("rax") = n;
    register long r10 __asm__("r10") = d;
    register long r8  __asm__("r8")  = e;
    __asm__ __volatile__("syscall" : "+r"(rax)
                         : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8) : ZNG_CLOB);
    return rax;
}
static inline long zng_sys6(long n, long a, long b, long c, long d, long e, long f)
{
    zng_tick(n);
    register long rax __asm__("rax") = n;
    register long r10 __asm__("r10") = d;
    register long r8  __asm__("r8")  = e;
    register long r9  __asm__("r9")  = f;
    __asm__ __volatile__("syscall" : "+r"(rax)
                         : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                         : ZNG_CLOB);
    return rax;
}

#endif

/* ------------------------------------------------------------------ */
/* 返回值判定（内核返回 -1..-4095 表示错误号）                          */
/* ------------------------------------------------------------------ */

static inline int zng_iserr(long r)
{
    return (unsigned long)r > (unsigned long)-4096UL;
}

/* ------------------------------------------------------------------ */
/* 常用 syscall 包装                                                   */
/* ------------------------------------------------------------------ */

static inline long zng_openat(int dfd, const char *p, long flags, long mode)
{ return zng_sys4(ZNG_NR_openat, dfd, (long)p, flags, mode); }

static inline long zng_close(int fd)
{ return zng_sys1(ZNG_NR_close, fd); }

static inline long zng_read(int fd, void *b, unsigned long n)
{ return zng_sys3(ZNG_NR_read, fd, (long)b, (long)n); }

static inline long zng_write(int fd, const void *b, unsigned long n)
{ return zng_sys3(ZNG_NR_write, fd, (long)b, (long)n); }

static inline long zng_lseek(int fd, long off, int whence)
{ return zng_sys3(ZNG_NR_lseek, fd, off, whence); }

static inline long zng_fstatat(int dfd, const char *p, struct zng_stat *st, long flags)
{ return zng_sys4(ZNG_NR_newfstatat, dfd, (long)p, (long)st, flags); }

static inline long zng_fstat(int fd, struct zng_stat *st)
{ return zng_sys2(ZNG_NR_fstat, fd, (long)st); }

static inline long zng_readlinkat(int dfd, const char *p, char *b, unsigned long n)
{ return zng_sys4(ZNG_NR_readlinkat, dfd, (long)p, (long)b, (long)n); }

static inline long zng_faccessat(int dfd, const char *p, long mode, long flags)
{ return zng_sys4(ZNG_NR_faccessat, dfd, (long)p, mode, flags); }

static inline long zng_getcwd(char *b, unsigned long n)
{ return zng_sys2(ZNG_NR_getcwd, (long)b, (long)n); }

static inline long zng_chdir(const char *p)
{ return zng_sys1(ZNG_NR_chdir, (long)p); }

static inline long zng_fchdir(int fd)
{ return zng_sys1(ZNG_NR_fchdir, fd); }

static inline long zng_dup3(int a, int b, long flags)
{ return zng_sys3(ZNG_NR_dup3, a, b, flags); }

static inline long zng_pipe2(int *fd, long flags)
{ return zng_sys2(ZNG_NR_pipe2, (long)fd, flags); }

static inline long zng_getdents64(int fd, void *b, unsigned long n)
{ return zng_sys3(ZNG_NR_getdents64, fd, (long)b, (long)n); }

static inline long zng_execve(const char *p, char *const av[], char *const ev[])
{ return zng_sys3(ZNG_NR_execve, (long)p, (long)av, (long)ev); }

static inline long zng_unlinkat(int dfd, const char *p, long flags)
{ return zng_sys3(ZNG_NR_unlinkat, dfd, (long)p, flags); }

static inline long zng_mkdirat(int dfd, const char *p, long mode)
{ return zng_sys3(ZNG_NR_mkdirat, dfd, (long)p, mode); }

static inline long zng_mknodat(int dfd, const char *p, long mode, long dev)
{ return zng_sys4(ZNG_NR_mknodat, dfd, (long)p, mode, dev); }

static inline long zng_renameat(int od, const char *o, int nd, const char *n)
{ return zng_sys4(ZNG_NR_renameat, od, (long)o, nd, (long)n); }
static inline long zng_renameat2(int od, const char *o, int nd, const char *n, unsigned f)
{ return zng_sys5(ZNG_NR_renameat2, od, (long)o, nd, (long)n, (long)f); }

static inline long zng_symlinkat(const char *t, int nd, const char *l)
{ return zng_sys3(ZNG_NR_symlinkat, (long)t, nd, (long)l); }

static inline long zng_linkat(int od, const char *o, int nd, const char *n, long f)
{ return zng_sys5(ZNG_NR_linkat, od, (long)o, nd, (long)n, f); }

static inline long zng_fchmodat(int dfd, const char *p, long mode, long flags)
{ return zng_sys4(ZNG_NR_fchmodat, dfd, (long)p, mode, flags); }

static inline long zng_fchownat(int dfd, const char *p, long u, long g, long f)
{ return zng_sys5(ZNG_NR_fchownat, dfd, (long)p, u, g, f); }

static inline long zng_utimensat(int dfd, const char *p, const long *ts, long f)
{ return zng_sys4(ZNG_NR_utimensat, dfd, (long)p, (long)ts, f); }

static inline long zng_truncate(const char *p, long len)
{ return zng_sys2(ZNG_NR_truncate, (long)p, len); }

static inline long zng_ftruncate(int fd, long len)
{ return zng_sys2(ZNG_NR_ftruncate, fd, len); }

static inline long zng_ioctl(int fd, long req, void *a)
{ return zng_sys3(ZNG_NR_ioctl, fd, req, (long)a); }

static inline long zng_fcntl(int fd, long cmd, long a)
{ return zng_sys3(ZNG_NR_fcntl, fd, cmd, a); }

static inline long zng_getpid(void)
{ return zng_sys0(ZNG_NR_getpid); }

static inline long zng_getuid(void)
{ return zng_sys0(ZNG_NR_getuid); }

static inline long zng_geteuid(void)
{ return zng_sys0(ZNG_NR_geteuid); }

static inline long zng_getgid(void)
{ return zng_sys0(ZNG_NR_getgid); }

static inline long zng_getegid(void)
{ return zng_sys0(ZNG_NR_getegid); }

static inline long zng_exit_group(int c)
{ return zng_sys1(ZNG_NR_exit_group, c); }

/* struct open_how for openat2 (Linux 5.6+) */
struct zng_open_how {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};

static inline long zng_openat2(int dfd, const char *p, struct zng_open_how *how)
{
    return zng_sys4(ZNG_NR_openat2, dfd, (long)p, (long)how,
                    (long)sizeof(struct zng_open_how));
}

/* ------------------------------------------------------------------ */
/* 宿主 libc 符号（运行时解析；均为我们不 hook 的名字，无递归风险）      */
/* ------------------------------------------------------------------ */

#ifndef ZNG_HOST_TEST   /* 单元测试链接真 libc，这些声明会与之冲突 */
extern void  *malloc(unsigned long);
extern void   free(void *);
#endif
extern char **environ;
extern char  *getenv(const char *);

#endif /* ZNG_SYS_H */
