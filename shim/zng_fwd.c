/* SPDX-License-Identifier: MIT */
/*
 * zng_fwd.c — 转发层：翻译路径后交给真 libc
 *
 * 为什么需要这一层：libc 内部（fopen 内部的 open、opendir 内部的 openat）
 * 发的是**直接调用**，不经过 PLT，我们的 open/openat 钩子截不到。
 * 所以对这些函数只能"翻译路径 + 转发真函数"。
 *
 * 这一层直接决定 Python / PyTorch 这类重负载能否跑起来：
 *
 *   · realpath      —— os.path.realpath / pathlib 解析
 *   · mkstemp 家族  —— tempfile 模块（PyTorch 用它做 mmap 临时文件）
 *   · dlopen        —— Python C 扩展加载（_C.cpython-*.so）
 *   · posix_spawn   —— subprocess 的部分路径
 *   · popen/system  —— subprocess、pip 调用外部工具
 *   · scandir/glob  —— 目录枚举
 *
 * [zroot-lab] 完全没有这一层（只做了 fopen/opendir 等少数几个）。
 * [zroot] 有 libzroot-fwd.c，思路相同，这里沿用并补全。
 */
#include "zng.h"
#include "zng_sys.h"

#define ZEXPORT __attribute__((visibility("default")))

extern void *dlsym(void *, const char *);
#define ZNG_RTLD_NEXT ((void *)-1L)

static void *zng_real(const char *name)
{
    void *p = dlsym(ZNG_RTLD_NEXT, name);
    if (!p) zng_set_errno(ZNG_ENOSYS);
    return p;
}

/* 把 guest 路径翻译成 host 路径；失败或无需翻译时返回原指针 */
static const char *tr(const struct zng_cfg *c, const char *path,
                      char *host, size_t hostn)
{
    if (!c || !path) return path;
    int r = zng_resolve(c, path, ZNG_AT_FDCWD, host, hostn);
    if (r < 0) return path;            /* 解析失败：用原路径，让 libc 报错 */
    return (r == 0) ? host : path;
}

/* host 结果转回 guest 视图（就地改写 buf；guest 一定不长于 host） */
static void untr(const struct zng_cfg *c, char *buf, size_t bufn)
{
    if (!c || !buf) return;
    char guest[ZNG_PATH_MAX];
    if (zng_untranslate(c, buf, guest, sizeof guest) == 1)
        zng_strlcpy(buf, guest, bufn);
}

/* ================================================================== */
/* realpath                                                            */
/* ================================================================== */

ZEXPORT char *realpath(const char *path, char *resolved)
{
    static char *(*rp)(const char *, char *) = 0;
    if (!rp) { rp = (char *(*)(const char *, char *))zng_real("realpath");
               if (!rp) return (char *)0; }

    struct zng_cfg *c = zng_cfg();
    if (!c || !path) return rp(path, resolved);

    char host[ZNG_PATH_MAX];
    char *out = rp(tr(c, path, host, sizeof host), resolved);
    if (!out) return (char *)0;

    /* resolved==NULL 时 libc 自行 malloc，guest 串更短，就地改写安全 */
    untr(c, out, zng_strlen(out) + 1);
    return out;
}

ZEXPORT char *canonicalize_file_name(const char *path)
{
    static char *(*cf)(const char *) = 0;
    if (!cf) { cf = (char *(*)(const char *))zng_real("canonicalize_file_name");
               if (!cf) return (char *)0; }
    struct zng_cfg *c = zng_cfg();
    if (!c || !path) return cf(path);
    char host[ZNG_PATH_MAX];
    char *out = cf(tr(c, path, host, sizeof host));
    if (out) untr(c, out, zng_strlen(out) + 1);
    return out;
}

ZEXPORT char *get_current_dir_name(void)
{
    static char *(*gc)(void) = 0;
    if (!gc) { gc = (char *(*)())zng_real("get_current_dir_name");
               if (!gc) return (char *)0; }
    char *out = gc();
    if (out) untr(zng_cfg(), out, zng_strlen(out) + 1);
    return out;
}

/* ================================================================== */
/* 临时文件                                                            */
/* ================================================================== */
/*
 * mkstemp 会**就地改写模板**（XXXXXX -> 随机字符，长度不变）。
 * 如果我们把 host 路径传给真函数，被改写的是我们的临时缓冲，
 * 调用方的 tpl 就还是原模板 —— 违反语义，Python 的 tempfile 会拿到错名字。
 * 所以必须调用后把结果转回 guest 视图再写回 tpl。
 */
static int mkstemp_common(char *tpl, int extra_flags, int suffix_len)
{
    struct zng_cfg *c = zng_cfg();
    char host[ZNG_PATH_MAX];
    int fd;

    if (!c || !tpl) {
        zng_set_errno(ZNG_EINVAL);
        return -1;
    }

    int r = zng_resolve(c, tpl, ZNG_AT_FDCWD, host, sizeof host);
    if (r != 0) {                       /* 无需翻译：直接转发 */
        if (suffix_len) {
            static int (*f4)(char *, int, int) = 0;
            if (!f4) { f4 = (int (*)(char *, int, int))zng_real("mkostemps");
                       if (!f4) return -1; }
            fd = f4(tpl, suffix_len, extra_flags);
        } else {
            static int (*f2)(char *, int) = 0;
            if (!f2) { f2 = (int (*)(char *, int))zng_real("mkostemp");
                       if (!f2) return -1; }
            fd = f2(tpl, extra_flags);
        }
        return fd;
    }

    if (suffix_len) {
        static int (*f4)(char *, int, int) = 0;
        if (!f4) { f4 = (int (*)(char *, int, int))zng_real("mkostemps");
                   if (!f4) return -1; }
        fd = f4(host, suffix_len, extra_flags);
    } else {
        static int (*f2)(char *, int) = 0;
        if (!f2) { f2 = (int (*)(char *, int))zng_real("mkostemp");
                   if (!f2) return -1; }
        fd = f2(host, extra_flags);
    }
    if (fd < 0) return fd;

    /* 写回：guest 与 host 只是前缀不同，长度差固定；这里 host 更长，
     * 转回 guest 后一定更短，所以原地写回不会越界。 */
    {
        char guest[ZNG_PATH_MAX];
        if (zng_untranslate(c, host, guest, sizeof guest) == 1)
            zng_strlcpy(tpl, guest, zng_strlen(tpl) + 1);
    }
    return fd;
}

ZEXPORT int mkstemp(char *tpl)    { return mkstemp_common(tpl, 0, 0); }
ZEXPORT int mkostemp(char *tpl, int flags) { return mkstemp_common(tpl, flags, 0); }
ZEXPORT int mkstemps(char *tpl, int slen)  { return mkstemp_common(tpl, 0, slen); }
ZEXPORT int mkostemps(char *tpl, int slen, int flags)
{ return mkstemp_common(tpl, flags, slen); }

/*
 * glibc 的 64 位变体：在 64 位平台上与不带后缀的版本等价，
 * 但**符号名不同**，必须一并导出。
 *
 * 【真机实测（Alpaquita glibc）发现的 bug】busybox 在 glibc 下请求的
 * 是 mkstemp64 —— LD_DEBUG=symbols 显示查找顺序为
 *     busybox -> libzng.so -> libcrypt -> libm -> libresolv -> libc.so.6
 * 我们只导出了 mkstemp，于是落到 glibc 的原实现，路径**不翻译**，
 * 结果是去写 Android 的 /tmp：
 *     mktemp /tmp/t.XXXXXX  ->  mktemp: : No such file or directory
 * 而 musl 没有 64 位变体，请求的就是 mkstemp，钩子正常生效 ——
 * 所以这个 bug 只在 glibc rootfs 下出现。
 */
ZEXPORT int mkstemp64(char *tpl) { return mkstemp_common(tpl, 0, 0); }
ZEXPORT int mkostemp64(char *tpl, int flags) { return mkstemp_common(tpl, flags, 0); }
ZEXPORT int mkstemps64(char *tpl, int slen) { return mkstemp_common(tpl, 0, slen); }
ZEXPORT int mkostemps64(char *tpl, int slen, int flags)
{ return mkstemp_common(tpl, flags, slen); }

/* ================================================================== */
/* 目录扫描                                                            */
/* ================================================================== */

struct zng_dirent64 {
    unsigned long  d_ino;
    long           d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[256];
};

ZEXPORT int scandir(const char *dir, struct zng_dirent64 ***nl,
                    int (*f)(const struct zng_dirent64 *),
                    int (*cmp)(const struct zng_dirent64 **,
                               const struct zng_dirent64 **))
{
    static int (*sd)(const char *, struct zng_dirent64 ***,
                     int (*)(const struct zng_dirent64 *),
                     int (*)(const struct zng_dirent64 **,
                             const struct zng_dirent64 **)) = 0;
    if (!sd) { *(void **)&sd = zng_real("scandir"); if (!sd) return -1; }
    struct zng_cfg *c = zng_cfg();
    char host[ZNG_PATH_MAX];
    return sd(tr(c, dir, host, sizeof host), nl, f, cmp);
}

ZEXPORT int scandirat(int dfd, const char *dir, struct zng_dirent64 ***nl,
                      int (*f)(const struct zng_dirent64 *),
                      int (*cmp)(const struct zng_dirent64 **,
                                 const struct zng_dirent64 **))
{
    static int (*sda)(int, const char *, struct zng_dirent64 ***,
                      int (*)(const struct zng_dirent64 *),
                      int (*)(const struct zng_dirent64 **,
                              const struct zng_dirent64 **)) = 0;
    if (!sda) { *(void **)&sda = zng_real("scandirat"); if (!sda) return -1; }
    struct zng_cfg *c = zng_cfg();
    if (!c || !dir || dir[0] == '/')
        return sda(dfd, dir, nl, f, cmp);      /* 绝对路径：dfd 被忽略 */

    /*
     * 相对路径 + 真实 dirfd：翻译目录名后仍要用原 dirfd。
     * 注意不能把 dfd 换成 AT_FDCWD —— 那会改变"相对于哪个目录"的语义。
     *（zroot-lab 在这里用 /proc/self/fd 桥接，引入了 /proc 挂载依赖；
     *  这里保守地保持 dfd 不变，只翻译目录名部分。）
     */
    char host[ZNG_PATH_MAX];
    return sda(dfd, tr(c, dir, host, sizeof host), nl, f, cmp);
}

/* ================================================================== */
/* glob / wordexp                                                      */
/* ================================================================== */

/*
 * pattern 含通配符（*?[]），整串翻译必然失败。
 * 正确做法：只翻译**最后一个 '/' 之前的目录部分**，basename 原样保留。
 */
static const char *tr_pattern(const struct zng_cfg *c, const char *pat,
                              char *out, size_t outn)
{
    const char *slash;
    size_t dl;
    char dpart[ZNG_PATH_MAX];
    int r;

    if (!c || !pat) return pat;
    slash = zng_strrchr(pat, '/');
    if (!slash) return pat;                    /* 无目录部分：按 cwd 解析 */

    dl = (size_t)(slash - pat);
    if (dl == 0) dl = 1;                       /* "/x*" -> 目录是 "/" */
    if (dl >= sizeof dpart) return pat;
    zng_memcpy(dpart, pat, dl);
    dpart[dl] = 0;

    r = zng_resolve(c, dpart, ZNG_AT_FDCWD, out, outn);
    if (r != 0) return pat;
    {
        size_t o = zng_strlen(out);
        if (o + zng_strlen(slash) + 1 > outn) return pat;
        zng_strcpy(out + o, slash);
    }
    return out;
}

ZEXPORT int glob(const char *pattern, int flags,
                 int (*errf)(const char *, int), void *pglob)
{
    static int (*gb)(const char *, int, int (*)(const char *, int), void *) = 0;
    if (!gb) { *(void **)&gb = zng_real("glob"); if (!gb) return -1; }
    struct zng_cfg *c = zng_cfg();
    char host[ZNG_PATH_MAX];
    return gb(tr_pattern(c, pattern, host, sizeof host), flags, errf, pglob);
}

ZEXPORT int glob64(const char *pattern, int flags,
                   int (*errf)(const char *, int), void *pglob)
{ return glob(pattern, flags, errf, pglob); }

/* ================================================================== */
/* popen / system                                                      */
/* ================================================================== */
/*
 * 命令字符串里的路径**不需要**翻译：它由 shell 解释，而 shell 是我们 exec
 * 出来的、已被注入 shim 的 rootfs 里的 shell，路径会在 shell 内部被翻译。
 * 翻译这里的字符串反而会破坏 "$HOME"、引号等 shell 语法。
 * 所以 popen/system 直接转发即可 —— 关键是子进程要继承 LD_PRELOAD，
 * 这由 zng_env_build 保证。
 */
ZEXPORT void *popen(const char *cmd, const char *mode)
{
    static void *(*po)(const char *, const char *) = 0;
    if (!po) { *(void **)&po = zng_real("popen"); if (!po) return (void *)0; }
    return po(cmd, mode);
}
ZEXPORT int pclose(void *f)
{
    static int (*pc)(void *) = 0;
    if (!pc) { *(void **)&pc = zng_real("pclose"); if (!pc) return -1; }
    return pc(f);
}
ZEXPORT int system(const char *cmd)
{
    static int (*sy)(const char *) = 0;
    if (!sy) { *(void **)&sy = zng_real("system"); if (!sy) return -1; }
    return sy(cmd);
}

/* ================================================================== */
/* posix_spawn                                                         */
/* ================================================================== */
/*
 * file_actions 是不透明结构，spawn 时无法再翻译其中已登记的路径。
 * 因此必须在 **addopen / addchdir_np 登记时就翻译**，spawn 只翻译可执行文件名。
 *
 * [zroot-lab] 的做法是手工 fork 模拟，代价是丢弃了 attr 里的全部语义
 * （POSIX_SPAWN_SETSID、调度策略、信号掩码、PGID），且 addfchdir 直接未实现。
 * 这里保留 libc 的真实实现，只做路径翻译 —— 语义完整得多。
 */
ZEXPORT int posix_spawn_file_actions_addopen(void *fa, int fd,
                                             const char *path,
                                             int flags, unsigned int mode)
{
    static int (*ao)(void *, int, const char *, int, unsigned int) = 0;
    if (!ao) { *(void **)&ao = zng_real("posix_spawn_file_actions_addopen");
               if (!ao) return ZNG_ENOSYS; }
    struct zng_cfg *c = zng_cfg();
    char host[ZNG_PATH_MAX];
    return ao(fa, fd, tr(c, path, host, sizeof host), flags, mode);
}

ZEXPORT int posix_spawn_file_actions_addchdir_np(void *fa, const char *path)
{
    static int (*ac)(void *, const char *) = 0;
    if (!ac) { *(void **)&ac = zng_real("posix_spawn_file_actions_addchdir_np");
               if (!ac) return ZNG_ENOSYS; }
    struct zng_cfg *c = zng_cfg();
    char host[ZNG_PATH_MAX];
    return ac(fa, tr(c, path, host, sizeof host));
}

ZEXPORT int posix_spawn(int *pid, const char *path, const void *fa,
                        const void *attr, char *const argv[], char *const envp[])
{
    static int (*ps)(int *, const char *, const void *, const void *,
                     char *const[], char *const[]) = 0;
    if (!ps) { *(void **)&ps = zng_real("posix_spawn"); if (!ps) return ZNG_ENOSYS; }
    struct zng_cfg *c = zng_cfg();
    char host[ZNG_PATH_MAX];
    return ps(pid, tr(c, path, host, sizeof host), fa, attr, argv, envp);
}

ZEXPORT int posix_spawnp(int *pid, const char *file, const void *fa,
                         const void *attr, char *const argv[], char *const envp[])
{
    static int (*psp)(int *, const char *, const void *, const void *,
                      char *const[], char *const[]) = 0;
    if (!psp) { *(void **)&psp = zng_real("posix_spawnp"); if (!psp) return ZNG_ENOSYS; }
    (void)zng_cfg();   /* PATH 搜索由 libc 完成，路径内含 '/' 时仍不翻译 */
    return psp(pid, file, fa, attr, argv, envp);
}

/* ================================================================== */
/* dlopen —— Python C 扩展加载的关键                                    */
/* ================================================================== */
/*
 * dlopen 的路径解析由 ld.so 完成，**不走我们的 open 钩子**：
 *   · "libfoo.so"（无斜杠）-> 按 LD_LIBRARY_PATH 搜索，已设为 rootfs 的
 *     lib 目录，**能正常工作**，无需干预；
 *   · "/abs/path.so"       -> 按真实根解析，rootfs 内的绝对路径在宿主上
 *     不存在 -> 失败。
 * 所以要 hook 的是第二种情况：翻译绝对路径。
 *
 * Python 导入 torch 时，_C.cpython-*.so 通常经包内相对路径解析（能工作），
 * 但显式 dlopen 绝对路径、或 RPATH 里含绝对路径时就会失败。
 */
ZEXPORT void *dlopen(const char *path, int flags)
{
    static void *(*dl)(const char *, int) = 0;
    if (!dl) { *(void **)&dl = zng_real("dlopen"); if (!dl) return (void *)0; }
    struct zng_cfg *c = zng_cfg();
    if (!c || !path || path[0] != '/') return dl(path, flags);
    char host[ZNG_PATH_MAX];
    return dl(tr(c, path, host, sizeof host), flags);
}

/* ================================================================== */
/* 杂项                                                                */
/* ================================================================== */

ZEXPORT int statvfs(const char *path, void *buf)
{
    static int (*sv)(const char *, void *) = 0;
    if (!sv) { *(void **)&sv = zng_real("statvfs"); if (!sv) return -1; }
    struct zng_cfg *c = zng_cfg();
    char host[ZNG_PATH_MAX];
    return sv(tr(c, path, host, sizeof host), buf);
}
ZEXPORT int statvfs64(const char *path, void *buf) { return statvfs(path, buf); }

/*
 * statfs：busybox df 用它（LD_DEBUG 实测绑定到 libc）。
 * 64 位平台上 glibc 的 statfs/statfs64 布局一致，转发即可。
 */
ZEXPORT int statfs(const char *path, void *buf)
{
    static int (*sf)(const char *, void *) = 0;
    if (!sf) { *(void **)&sf = zng_real("statfs"); if (!sf) return -1; }
    struct zng_cfg *c = zng_cfg();
    char host[ZNG_PATH_MAX];
    return sf(tr(c, path, host, sizeof host), buf);
}
ZEXPORT int statfs64(const char *path, void *buf) { return statfs(path, buf); }

ZEXPORT int utime(const char *path, const void *times)
{
    static int (*ut)(const char *, const void *) = 0;
    if (!ut) { *(void **)&ut = zng_real("utime"); if (!ut) return -1; }
    struct zng_cfg *c = zng_cfg();
    char host[ZNG_PATH_MAX];
    return ut(tr(c, path, host, sizeof host), times);
}

ZEXPORT int mkfifo(const char *path, unsigned mode)
{
    static int (*mf)(const char *, unsigned) = 0;
    if (!mf) { *(void **)&mf = zng_real("mkfifo"); if (!mf) return -1; }
    struct zng_cfg *c = zng_cfg();
    char host[ZNG_PATH_MAX];
    return mf(tr(c, path, host, sizeof host), mode);
}

/*
 * 以下三个不走转发，直接用 syscall 封装实现。
 * 原因：truncate / utimensat 与 GCC 内建函数同名，在 -ffreestanding 下
 * 声明会被忽略（表现为 implicit declaration），跨文件调用 zng_hooks.c 里的
 * 同名符号并不可靠。这里干脆各写一遍路径解析，代价是几行重复。
 */
ZEXPORT int truncate64(const char *path, long long len)
{
    struct zng_cfg *c = zng_cfg();
    if (!c || !path) return zng_ret(zng_truncate(path, (long)len));
    char host[ZNG_PATH_MAX];
    int r = zng_resolve(c, path, ZNG_AT_FDCWD, host, sizeof host);
    if (r < 0) { zng_set_errno(-r); return -1; }
    return zng_ret(zng_truncate((r == 0) ? host : path, (long)len));
}

ZEXPORT int utimes(const char *path, const long long *tv)
{
    struct zng_cfg *c = zng_cfg();
    if (!c || !path) return zng_ret(zng_utimensat(ZNG_AT_FDCWD, path,
                                                  (const long *)tv, 0));
    char host[ZNG_PATH_MAX];
    int r = zng_resolve(c, path, ZNG_AT_FDCWD, host, sizeof host);
    if (r < 0) { zng_set_errno(-r); return -1; }
    return zng_ret(zng_utimensat(ZNG_AT_FDCWD, (r == 0) ? host : path,
                                 (const long *)tv, 0));
}

ZEXPORT int lutimes(const char *path, const long long *tv)
{
    struct zng_cfg *c = zng_cfg();
    if (!c || !path)
        return zng_ret(zng_utimensat(ZNG_AT_FDCWD, path, (const long *)tv,
                                     ZNG_AT_SYMLINK_NOFOLLOW));
    char host[ZNG_PATH_MAX];
    int r = zng_resolve(c, path, ZNG_AT_FDCWD, host, sizeof host);
    if (r < 0) { zng_set_errno(-r); return -1; }
    return zng_ret(zng_utimensat(ZNG_AT_FDCWD, (r == 0) ? host : path,
                                 (const long *)tv, ZNG_AT_SYMLINK_NOFOLLOW));
}
