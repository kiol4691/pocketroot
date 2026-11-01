/* SPDX-License-Identifier: MIT */
/*
 * zng_run.c — 路径解析（双引擎）与 exec 执行
 *
 * 这一层才真正发起 syscall，因此是唯一需要关心 Android 环境细节的地方。
 */
#include "zng.h"
#include "zng_sys.h"

/* ================================================================== */
/* openat2 能力探测与 rootfd 管理                                      */
/* ================================================================== */

/* exec 时一次读入的 ELF 头部块大小：覆盖 ehdr + phdr 表 + PT_INTERP 数据 */
#define ZNG_ELF_CHUNK 4096

static int  g_have_openat2 = -1;   /* -1 未知, 0 无, 1 有 */
static int  g_rootfd = -1;

void zng_resolver_init(const struct zng_cfg *c)
{
    if (!c || c->root_len == 0) { g_have_openat2 = 0; return; }

    /*
     * 默认**不启用** Engine A（openat2）。
     *
     * 【真机实测的致命 bug】原先这里无条件调用 openat2 做能力探测：
     *     long r = zng_openat2(g_rootfd, ".", &how);
     * 但 openat2(437) 很可能不在 Android app 的 zygote seccomp 白名单内，
     * 一旦被拦截就是 SIGSYS —— 进程当场被杀，**根本没有机会降级**。
     * 表现为：shell 一启动就死（exit=159），zng.log 只被创建（log_init
     * 成功）却空无一物。
     *
     * 注意 adb shell 里完全测不出来 —— adb shell 不是 app 进程，
     * 没有 zygote 装的那套 seccomp 过滤器。这是"真机 App 环境"独有的
     * 失败模式，也是本项目必须上真机验证的根本原因。
     *
     * 而 Engine B（translate + 交给内核解析）在本项目中是安全的：
     * 构建期已把 rootfs 内部的**绝对**符号链接全部改写成**相对**链接
     * （tools/rewrite-symlinks.py），内核解析相对链接不会逃出 rootfs，
     * 因此并不需要 RESOLVE_IN_ROOT 的额外保护。
     *
     * 若确认目标设备的 openat2 可用（先用独立探针验证），可用
     * ZNG_OPENAT2=1 显式启用 Engine A 以换取 TOCTOU 方面的收益。
     */
    g_have_openat2 = 0;

    const char *v = getenv("ZNG_OPENAT2");
    if (v && v[0] == '1') {
        g_rootfd = (int)zng_openat(ZNG_AT_FDCWD, c->root,
                                   ZNG_O_PATH | ZNG_O_DIRECTORY | ZNG_O_CLOEXEC, 0);
        if (zng_iserr(g_rootfd)) {
            g_rootfd = -1;
            zng_log2("resolver: cannot open rootfd:", c->root);
            return;
        }
        struct zng_open_how how;
        how.flags = ZNG_O_PATH;
        how.mode = 0;
        how.resolve = ZNG_RESOLVE_IN_ROOT;
        long r = zng_openat2(g_rootfd, ".", &how);
        if (!zng_iserr(r)) {
            zng_close((int)r);
            g_have_openat2 = 1;
            if (c->debug) zng_log("resolver: engine A (openat2 RESOLVE_IN_ROOT)\n");
            return;
        }
        if (c->debug) zng_log("resolver: openat2 不可用，回退 engine B\n");
    }
    /*
     * 引擎选择属于诊断信息，**不能无条件往 stderr 打**。
     *
     * 【真机实测发现的 bug】原先无条件打印，于是每一个新进程启动都会
     * 往 stderr 输出一行 —— 任何 `x=$(cmd 2>&1)` 的第一行都是这条日志，
     * 真实输出被 `head -1` 之类截掉，表现为各种命令"莫名返回空"。
     * 这正是我在文档里批评 zroot-lab 的"日志污染 stderr"，
     * 结果自己在 resolver_init 里重犯了一遍。
     */
    if (c->debug) zng_log("resolver: engine B (translate + 内核解析)\n");
}

/*
 * rootfd 会被子进程关掉（close_fds / daemonize），故需要懒重开。
 * 注意"旧 fd 号可能已被子进程复用并重新分配成同一个号" —— 不能盲目关闭。
 */
static long rootfd_openat2(const struct zng_cfg *c, const char *rel,
                           long flags, long mode, long resolve)
{
    struct zng_open_how how;
    how.flags = (uint64_t)flags;
    how.mode = (uint64_t)mode;
    how.resolve = (uint64_t)resolve;

    long r = zng_openat2(g_rootfd, rel, &how);
    if (r == -ZNG_EBADF && c->root_len > 0) {
        long fd2 = zng_openat(ZNG_AT_FDCWD, c->root,
                              ZNG_O_PATH | ZNG_O_DIRECTORY | ZNG_O_CLOEXEC, 0);
        if (!zng_iserr(fd2)) {
            if (g_rootfd >= 0 && g_rootfd != (int)fd2) zng_close(g_rootfd);
            g_rootfd = (int)fd2;
            r = zng_openat2(g_rootfd, rel, &how);
        }
    }
    return r;
}

/*
 * Engine A 失败的降级判定。
 * 只有这几种 errno 才说明"路径穿过了 bind" —— bind 是纯路径重写，内核在
 * rootfs 内看不到它，所以必须由用户态兜底。其他错误是真实错误，不应降级
 * （[B] 没有 Engine A，也就没有这个概念；[A] 的降级条件在这里被显式化）。
 */
static int should_fallback(long r)
{
    return r == -ZNG_ENOENT || r == -ZNG_ENOTDIR ||
           r == -ZNG_ELOOP  || r == -ZNG_EXDEV;
}

/* 相对 openat2 路径：host 路径去掉 root 前缀 */
static const char *rel_under_root(const struct zng_cfg *c, const char *host)
{
    const char *rel = host + c->root_len;
    if (*rel == 0) return ".";
    if (*rel == '/') rel++;
    if (*rel == 0) return ".";
    return rel;
}

/* /proc/self/fd/NN —— 用显式拼接，绝不用 snprintf 拼 format（A 就栽在这） */
static int mkfdpath(char *b, size_t bn, int fd)
{
    static const char pre[] = "/proc/self/fd/";
    size_t i = 0;
    while (pre[i]) { if (i + 1 >= bn) return -1; b[i] = pre[i]; i++; }
    char tmp[24];
    int k = 0;
    unsigned long v = (unsigned long)(fd < 0 ? 0 : fd);
    if (v == 0) tmp[k++] = '0';
    while (v) { tmp[k++] = (char)('0' + (v % 10)); v /= 10; }
    while (k) { if (i + 1 >= bn) return -1; b[i++] = tmp[--k]; }
    if (i + 1 >= bn) return -1;
    b[i] = 0;
    return 0;
}

/* ================================================================== */
/* 解析：guest 路径 -> 已解析的 host 路径                               */
/* ================================================================== */

/*
 * 返回： 0 = out 是解析后的 host 绝对路径（配合 AT_FDCWD 使用）
 *        1 = 原样透传（用调用方原来的 dirfd + path）
 *       <0 = -errno
 */
int zng_resolve(const struct zng_cfg *c, const char *path, int dirfd,
                char *out, size_t outn)
{
    if (!c || !path || !out || outn == 0) return -ZNG_EINVAL;
    if (c->root_len == 0) return 1;                 /* 惰性 */

    /*
     * dirfd 保留在接口上，但当前实现不直接使用它：相对路径一律透传。
     * 原因：相对路径要么基于进程 cwd（它本来就在 rootfs 里），要么基于
     * dirfd —— 而 dirfd 指向的是内核视角的真实目录，内核自己会解析正确。
     * 只有"dirfd 指向 rootfs 内、且路径里有需要重定向的绝对符号链接"
     * 才需要介入，那是后续版本的事（A 为此用 /proc/self/fd 桥接，会引入
     * 对 /proc 挂载的硬依赖，这里暂时不引入）。
     */
    (void)dirfd;

    char host[ZNG_PATH_MAX];
    int r = zng_translate(c, path, host, sizeof host);
    if (r < 0) return r;

    if (path[0] != '/') {
        /*
         * 相对路径：内核会基于进程的 cwd（它本来就在 rootfs 里）或 dirfd
         * 解析，语义天然正确 —— 原样透传即可（与 proot 一致）。
         */
        return 1;
    }

    if (r == 0) {
        /* 未改写：幂等（已是 host 视图）或 bind 到 host 目录 */
        long cp = zng_strlcpy(out, host, outn);
        return cp < 0 ? -ZNG_ENAMETOOLONG : 0;
    }

    if (g_have_openat2 != 1 || !zng_under_root(c, host)) {
        /* bind 出去的路径，或没有 openat2：直接交内核 */
        long cp = zng_strlcpy(out, host, outn);
        return cp < 0 ? -ZNG_ENAMETOOLONG : 0;
    }

    /* Engine A：让内核以 rootfs 为根解析，顺便解决符号链接逃逸 */
    {
        const char *rel = rel_under_root(c, host);
        long fd = rootfd_openat2(c, rel,
                                 ZNG_O_PATH | ZNG_O_CLOEXEC, 0,
                                 ZNG_RESOLVE_IN_ROOT);
        if (!zng_iserr(fd)) {
            char fdpath[64];
            long ret = -ZNG_ENAMETOOLONG;
            if (mkfdpath(fdpath, sizeof fdpath, (int)fd) == 0) {
                long rl = zng_readlinkat(ZNG_AT_FDCWD, fdpath, out, outn - 1);
                if (rl > 0) { out[rl] = 0; ret = 0; }
            }
            zng_close((int)fd);
            if (ret == 0) return 0;
        } else if (!should_fallback(fd)) {
            return (int)fd;
        }
        /* 落到下面降级 */
    }

    /* Engine B 兜底：直接给出未解析的 host 路径，让内核自己走 */
    long cp = zng_strlcpy(out, host, outn);
    return cp < 0 ? -ZNG_ENAMETOOLONG : 0;
}

/* 打开 guest 路径，返回 fd（>=0）或 -errno */
int zng_open_guest(const struct zng_cfg *c, const char *path, int dirfd,
                   long flags, long mode)
{
    if (!c || !path) return -ZNG_EINVAL;
    if (c->root_len == 0)
        return (int)zng_openat(dirfd, path, flags, mode);

    char host[ZNG_PATH_MAX];
    int r = zng_translate(c, path, host, sizeof host);
    if (r < 0) return r;

    if (path[0] != '/')
        return (int)zng_openat(dirfd, path, flags, mode);   /* 相对：原样 */

    /*
     * 兜底：非 O_CREAT / O_TMPFILE 时把 mode 清零。
     * 内核 openat2 规定此时 how.mode 必须为 0，否则返回 -EINVAL。
     * 调用方（含我们的变参解析）万一传了非零值，这里兜住。
     */
    if (!(flags & (ZNG_O_CREAT | ZNG_O_TMPFILE))) mode = 0;

    if (g_have_openat2 == 1 && zng_under_root(c, host)) {
        /*
         * 直接用 openat2 打开 —— 解析与打开是**同一个 syscall**，
         * 消除了"先解析路径、再打开"的 TOCTOU 窗口。
         * [A] 的 zt_open_guest 也是这个思路，这里沿用。
         */
        const char *rel = rel_under_root(c, host);
        long fd = rootfd_openat2(c, rel, flags, mode, ZNG_RESOLVE_IN_ROOT);
        if (c->debug) { zng_log2("dbg open: path =", path); zng_log2("dbg open: host =", host);
            zng_log("dbg open: via openat2 rc="); zng_logn(fd); zng_log("\n"); }
        if (!zng_iserr(fd)) return (int)fd;
        if (!should_fallback(fd)) return (int)fd;
        /* 穿过 bind 的符号链接 -> 降级到普通 openat(host) */
    }
    long r2 = zng_openat(ZNG_AT_FDCWD, host, flags, mode);
    if (c->debug) { zng_log2("dbg open: path =", path); zng_log2("dbg open: host =", host);
        zng_log("dbg open: flags="); zng_logn(flags);
        zng_log(" plain rc="); zng_logn(r2); zng_log("\n"); }
    return (int)r2;
}

/* ================================================================== */
/* exec                                                                */
/* ================================================================== */

/* 读入文件头部；返回读入字节数（可能小于 want），或 -errno */

/* 从 host 文件的指定偏移读取 want 字节；返回读入字节数或 -errno。
 * 用于定点读取 PT_INTERP 字符串（它的位置在 phdr 表之后）。 */

/* 解析 #! 行；返回 0 成功 */
static int parse_shebang(const unsigned char *buf, size_t n,
                         char *interp, size_t isz, char *iarg, size_t iasz)
{
    if (n < 2 || buf[0] != '#' || buf[1] != '!') return -ZNG_ENOEXEC;
    size_t i = 2;
    while (i < n && (buf[i] == ' ' || buf[i] == '\t')) i++;
    size_t st = i;
    while (i < n && buf[i] != ' ' && buf[i] != '\t' && buf[i] != '\n') i++;
    if (i == st) return -ZNG_ENOEXEC;
    if (i - st >= isz) return -ZNG_ENAMETOOLONG;
    zng_memcpy(interp, buf + st, i - st);
    interp[i - st] = 0;
    iarg[0] = 0;

    while (i < n && (buf[i] == ' ' || buf[i] == '\t')) i++;
    if (i < n && buf[i] != '\n') {
        size_t as = i;
        while (i < n && buf[i] != '\n' && buf[i] != ' ' && buf[i] != '\t') i++;
        if (i - as >= iasz) return -ZNG_ENAMETOOLONG;
        zng_memcpy(iarg, buf + as, i - as);
        iarg[i - as] = 0;
    }
    if (interp[0] != '/') return -ZNG_ENOEXEC;   /* 内核也要求绝对路径 */
    return 0;
}

/*
 * 执行 guest 路径上的程序。
 *
 * 与 A / B 的关键差异：**遇到静态二进制返回 -ENOSYS，而不是猜**。
 *   [A] ZT_HOSTNATIVE 会把"rootfs 里找不到解释器"当成"用 host libc 跑"，
 *       结果是 ABI 不匹配的诡异崩溃，且无从定位。
 *   [B] 直接放弃（无 PT_INTERP 支持概念）。
 * 这里把它变成一个明确的、带日志的错误 —— fail-visible。
 */
/*
 * 执行 host 路径上的程序：读 ELF -> 定位 PT_INTERP -> 映射到 host ->
 * 经 ldso 中继 execve。只在失败时返回。
 *
 * 抽成公共函数，是为了让"直接执行 ELF"与"shebang 的解释器"共用同一套中继
 * 逻辑。这两条路漏掉任何一条，都会表现为"某些命令能跑、某些不能"，
 * 极难定位 —— shebang 那一条先前正是如此（见 zng_exec_core 中的注释）。
 */
static int exec_host(const struct zng_cfg *c, const char *prog_host,
                     int fd_in, const unsigned char *pre, size_t prelen,
                     char *const argv[], char *const envp[])
{
    /*
     * 一次 open 读完 ELF 头 + phdr 表 + PT_INTERP 数据。
     *
     * 原实现是 read_head(64) -> read_head(span) -> read_at(interp) 三次
     * 各自 open/read/close，加上后面一次 faccessat：**每条外部命令 exec 之前
     * 就要付 12 个 syscall**（3+3+4+1+execve）。shell 循环跑命令时这部分
     * 直接叠在每条命令的启动开销上。
     *
     * 现在：1 次 open + 1 次 read（4KB 覆盖几乎所有 ELF 的 phdr+interp），
     * 只有 span 超过 4KB 时才在同一 fd 上补读，最后 1 次 close。
     */
    unsigned char small[ZNG_ELF_CHUNK];
    unsigned char *buf = small;
    size_t bufsz = sizeof small;
    int heap = 0;

    /*
     * fd_in >= 0 表示调用方已经打开文件、并读走了前 prelen 字节（判类型那次）。
     * 这里直接接着用，**所有权转移**：本函数返回前一律负责 close。
     * 于是每条 ELF exec 的 open 从 2 次降到 1 次、判类型的那次 read 也不再重读。
     */
    long fd = (fd_in >= 0) ? (long)fd_in
            : zng_openat(ZNG_AT_FDCWD, prog_host, ZNG_O_RDONLY | ZNG_O_CLOEXEC, 0);
    if (zng_iserr(fd)) return (int)fd;

    long got = 0;
    if (fd_in >= 0 && pre && prelen) {
        if (prelen > bufsz) prelen = bufsz;      /* 防御：调用方只传 512 */
        zng_memcpy(buf, pre, prelen);
        got = (long)prelen;
    }
    while ((size_t)got < bufsz) {
        long r = zng_read((int)fd, buf + got, bufsz - (size_t)got);
        if (zng_iserr(r)) { zng_close((int)fd); if (heap) zng_free_bytes(buf); return (int)r; }
        if (r == 0) break;
        got += r;
    }

    if (got < 4 || buf[0] != 0x7f || buf[1] != 'E' || buf[2] != 'L' || buf[3] != 'F') {
        zng_close((int)fd);
        if (heap) zng_free_bytes(buf);
        return -ZNG_ENOEXEC;
    }

    long span = zng_elf_span(buf, (size_t)got);
    if (span < 0) { zng_close((int)fd); if (heap) zng_free_bytes(buf); return (int)span; }

    /* span 超过 4KB（phnum 很大）：换到堆上把这个 span 读全。 */
    if ((size_t)span > (size_t)got) {
        if (span > (16L << 20)) { zng_close((int)fd); return -ZNG_ENOMEM; }
        unsigned char *big = (unsigned char *)zng_alloc_bytes((unsigned long)span);
        if (!big) { zng_close((int)fd); return -ZNG_ENOMEM; }
        long r = zng_lseek((int)fd, 0, 0);
        if (zng_iserr(r)) { zng_close((int)fd); zng_free_bytes(big); return (int)r; }
        got = 0;
        while ((size_t)got < (size_t)span) {
            r = zng_read((int)fd, big + got, (size_t)span - (size_t)got);
            if (zng_iserr(r)) { zng_close((int)fd); zng_free_bytes(big); return (int)r; }
            if (r == 0) break;
            got += r;
        }
        buf = big;
        bufsz = (size_t)span;
        heap = 1;
    }

    uint64_t ioff = 0, isz = 0;
    int kind = zng_elf_interp_loc(buf, (size_t)got, &ioff, &isz);

    char interp[256];
    if (kind == ZNG_ELF_STATIC) {
        zng_close((int)fd);
        if (heap) zng_free_bytes(buf);
    } else if (kind < 0) {
        zng_close((int)fd);
        if (heap) zng_free_bytes(buf);
        return kind;
    } else {
        if (isz == 0 || isz > sizeof interp) {
            zng_close((int)fd);
            if (heap) zng_free_bytes(buf);
            return -ZNG_ENAMETOOLONG;
        }
        /* PT_INTERP 的数据通常在 phdr 表之后；已在缓冲里就直接拷，否则补读。 */
        if (ioff + isz <= (uint64_t)got) {
            zng_memcpy(interp, buf + ioff, (size_t)isz);
        } else {
            long r = zng_lseek((int)fd, (long)ioff, 0);
            if (zng_iserr(r)) { zng_close((int)fd); if (heap) zng_free_bytes(buf); return (int)r; }
            long g3 = 0;
            while ((size_t)g3 < (size_t)isz) {
                r = zng_read((int)fd, interp + g3, (size_t)isz - (size_t)g3);
                if (zng_iserr(r)) { zng_close((int)fd); if (heap) zng_free_bytes(buf); return (int)r; }
                if (r == 0) break;
                g3 += r;
            }
            if ((size_t)g3 < (size_t)isz) {
                zng_close((int)fd);
                if (heap) zng_free_bytes(buf);
                return -ZNG_ENOEXEC;
            }
        }
        interp[isz - 1] = 0;                 /* PT_INTERP 自带 NUL */
        zng_close((int)fd);
        if (heap) zng_free_bytes(buf);
    }


    /* 解释器 -> host 路径（保留 symlink；不存在时退回 resolve） */
    char ihost[ZNG_PATH_MAX];
    int ir = zng_translate(c, interp, ihost, sizeof ihost);
    if (ir < 0) {
        zng_log2("exec: interpreter missing in rootfs:", interp);
        return ir;
    }
    if (ir == 0) {
        long cp = zng_strlcpy(ihost, interp, sizeof ihost);
        if (cp < 0) return -ZNG_ENAMETOOLONG;
    }
    /*
     * 这里刻意**不再**先 faccessat 探测解释器是否存在：那是每条 exec 多付
     * 一个 syscall，只为把"rootfs 缺解释器"的错误信息说得更漂亮。
     * 现在让 execve 自己失败，再按 errno 诊断（见下方）。
     */

    struct zng_plan plan;
    int pr = zng_plan_build(c, prog_host, ihost, argv, envp, &plan);
    if (pr < 0) return pr;

    if (c->debug) zng_log2("exec: relay", plan.argv[0]);

    zng_count_flush();
    long e = zng_execve(plan.argv[0], plan.argv, plan.envp);
    zng_plan_free(&plan);        /* 失败路径必须释放（A 只 free 了 nargv） */
    if (zng_iserr(e)) {
        /*
         * 失败才做诊断：interpreter 在 rootfs 里缺失时给出可读原因
         * （[A] 会去 host 上找同名文件并判定 ZT_HOSTNATIVE —— 把"rootfs
         *  不完整"伪装成一次成功，最终以 ABI 不匹配的崩溃收场）。
         */
        int irr = zng_resolve(c, interp, ZNG_AT_FDCWD, ihost, sizeof ihost);
        if (irr < 0) zng_log2("exec: interpreter missing in rootfs:", interp);
    }
    return zng_iserr(e) ? (int)e : 0;
}

int zng_exec_core(const struct zng_cfg *c, const char *path,
                  char *const argv[], char *const envp[], int do_search)
{
    (void)do_search;   /* PATH 搜索由 zng_execvp 负责，这里只处理具体路径 */

    if (!c || !path || !path[0]) return -ZNG_ENOENT;

    /*
     * 程序路径用 zng_translate（前缀翻译）而**不是** zng_resolve
     * （符号链接解析）—— 这是真机实测发现的 bug：
     *
     *   /bin/ls 是指向 busybox 的符号链接。若在此处把 symlink 解析掉，
     *   传给加载器的就变成 .../bin/busybox，busybox 于是认为自己是
     *   "busybox"，转而去把 argv[1] 当作 applet 名，结果是每条外部命令都报
     *     "/: applet not found"、"-a: applet not found" ...
     *   （极具迷惑性：看起来像 busybox 坏了，实际是 exec 引擎多解析了一层）
     *
     * 保留 symlink、让内核在 execve 时解析，才能维持正确的 argv[0] 语义，
     * 使 busybox 的 applet 分派照常工作。
     */
    char resolved[ZNG_PATH_MAX];
    {
        int r = zng_translate(c, path, resolved, sizeof resolved);
        if (r < 0) return r;
        if (r == 0) {                  /* 未改写（相对路径/已是 host 视图） */
            long cp = zng_strlcpy(resolved, path, sizeof resolved);
            if (cp < 0) return -ZNG_ENAMETOOLONG;
        }
    }

    /*
     * 读文件头：判断是 ELF 还是 "#!" 脚本。
     * 一次 open + 一次 read 就够 —— 原先先读 64 字节判类型、再读 512 字节
     * 取 shebang 行，等于每条脚本命令额外付一次 open/read/close。
     * 读 4KB（ZNG_ELF_CHUNK）：既覆盖 ELF magic 与 shebang 行，也一次把
     * phdr 表和 PT_INTERP 数据读进来 —— 后面 exec_host 直接复用这份缓冲，
     * 不再二次 read。
     */
    unsigned char sbuf[ZNG_ELF_CHUNK];
    long got;
    /*
     * 探测用的 fd 刻意**不在这里关**：ELF 分支把它连同已读到的 512 字节
     * 一起交给 exec_host，省掉一次 open + 一次 read。
     */
    long dfd = zng_openat(ZNG_AT_FDCWD, resolved, ZNG_O_RDONLY | ZNG_O_CLOEXEC, 0);
    if (zng_iserr(dfd)) return (int)dfd;
    got = 0;
    while ((size_t)got < sizeof sbuf) {
        long r = zng_read((int)dfd, sbuf + got, sizeof sbuf - (size_t)got);
        if (zng_iserr(r)) { zng_close((int)dfd); return (int)r; }
        if (r == 0) break;
        got += r;
    }
    unsigned char *head = sbuf;

    /* ---- ELF：整条路径交给 exec_host（含 PT_INTERP 探测 + ldso 中继） ---- */
    if (got >= 4 && head[0] == 0x7f && head[1] == 'E' &&
        head[2] == 'L' && head[3] == 'F') {
        return exec_host(c, resolved, (int)dfd, sbuf, (size_t)got, argv, envp);
    }

    /* 非 ELF：判类型用完即关 */
    zng_close((int)dfd);

    /* ---- "#!" 脚本 ---- */
    if (got >= 2 && head[0] == '#' && head[1] == '!') {
        long g2 = got;

        char interp[256], iarg[256];
        if (parse_shebang(sbuf, (size_t)g2, interp, sizeof interp,
                          iarg, sizeof iarg) < 0)
            return -ZNG_ENOEXEC;

        /*
         * 解释器 -> host 路径。
         * 用 translate 保留 symlink：/bin/sh 是指向 busybox 的链接，
         * busybox 靠 argv[0] 的 basename 分派 applet，解析掉 symlink
         * 会让它分派到错误的 applet。
         */
        char ihost[ZNG_PATH_MAX];
        int ir = zng_translate(c, interp, ihost, sizeof ihost);
        if (ir < 0) return ir;
        if (ir == 0) {
            long cp = zng_strlcpy(ihost, interp, sizeof ihost);
            if (cp < 0) return -ZNG_ENAMETOOLONG;
        }
        /* 同样不做 faccessat 预探测：解释器缺失时由 execve 的 errno 暴露 */

        /*
         * argv 布局：[argv0(占位), 脚本路径, 原 argv[1..]]
         * 脚本路径保持 **guest 视图**，解释器看到的 $0 才是 guest 路径。
         * nav[0] 会被 exec_host 内部替换成 prog_host，这里仅作占位。
         */
        int argc = 0;
        if (argv) for (char *const *a = argv; *a; a++) argc++;
        char **nav = (char **)zng_alloc_bytes(sizeof(char *) * (unsigned long)(argc + 4));
        if (!nav) return -ZNG_ENOMEM;
        int m = 0;
        nav[m++] = (char *)interp;
        if (iarg[0]) nav[m++] = iarg;
        nav[m++] = (char *)path;
        for (int i = 1; i < argc; i++) nav[m++] = argv[i];
        nav[m] = (char *)0;

        char **nenv = zng_env_build(c, envp);
        if (!nenv) { zng_free_bytes(nav); return -ZNG_ENOMEM; }

        /*
         * 关键：解释器本身是**动态链接**的（busybox 链接 musl），
         * 必须经 ldso 中继启动。
         *
         * 【真机实测的 bug】原先这里直接 execve(ihost) —— 内核会按真实根
         * 去解析它的 PT_INTERP=/lib/ld-musl-aarch64.so.1，在 Android 上
         * 不存在，execve 返回 ENOENT。表现为执行 shebang 脚本
         * "not found"，而显式 `/bin/sh script` 却正常 —— 后者走的是完整
         * 的 ELF 分支，那里有 ldso 中继。
         */
        int r = exec_host(c, ihost, -1, (const unsigned char *)0, 0, nav, nenv);
        zng_free_bytes(nav);
        zng_env_free(nenv);
        return r;
    }

    return -ZNG_ENOEXEC;
}
