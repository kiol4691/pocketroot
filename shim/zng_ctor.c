/* SPDX-License-Identifier: MIT */
/*
 * zng_ctor.c — 构造期初始化、日志、argv[0] 分级修复
 *
 * 关键设计：**未配置 ZNG_ROOT 时完全惰性**。
 *   shim 被误注入到 host 进程（或 rootfs 尚未就绪）时，zng_cfg() 返回
 *   NULL，所有 hook 直接转发原实现，不产生任何副作用。
 *   [B] 用 z_on 标志做了类似的事；[A] 在 libzroot.c 里也有 inert 分支，
 *   但它的 zt_ctor 里有 `if (zt_g.fake_root || 1)` —— 那个 `|| 1` 让
 *   栈回溯**永远执行**，与是否启用无关，属于未清理的调试残留。
 */
#include "zng.h"
#include "zng_sys.h"

extern void *dlsym(void *, const char *);
#define ZNG_RTLD_DEFAULT ((void *)0)

/* ================================================================== */
/* 全局只读配置                                                        */
/* ================================================================== */

/*
 * syscall 计数（定义处）。放在 zng_ctor.c：它是唯一必定被链接进来的
 * 翻译单元（ctor 必须存在），避免再给 zng_core.c 加一个 include。
 */
unsigned long zng_sc[512];
int           zng_sc_on;

static struct zng_cfg  g_cfg;
static int             g_ready;

struct zng_cfg *zng_cfg(void) { return g_ready ? &g_cfg : (struct zng_cfg *)0; }

/* ================================================================== */
/* 日志                                                                */
/* ================================================================== */
/*
 * [B 0.1.8] 把 ZROOT_DEBUG 常开，日志直接打到 stderr —— 于是 shell 的正常
 * 输出和 relay 日志混在一起。那是为了取证而做的妥协，代价是可用性。
 * => 这里支持 ZNG_LOG=<path> 把日志写到独立文件，stderr 保持干净。
 */
static int g_logfd = 2;

/*
 * 进程退出时把 syscall 计数写进日志（每行一个进程）：
 *   zngcnt pid=123 56=4 63=1 221=1
 * 数字是原始 syscall 号，配合 aarch64 编号表阅读。
 */
static void zng_count_emit(const char *tag)
{
    if (!zng_sc_on) return;
    zng_sc_on = 0;                    /* 别把 dump 自己的 syscall 算进去 */
    int any = 0;
    for (int i = 0; i < 512; i++) if (zng_sc[i]) { any = 1; break; }
    if (!any) return;
    zng_log("zngcnt ");
    zng_log(tag);
    zng_log(" pid=");
    zng_logn((long)zng_sys0(ZNG_NR_getpid));
    for (int i = 0; i < 512; i++) {
        if (!zng_sc[i]) continue;
        zng_log(" ");
        zng_logn((long)i);
        zng_log("=");
        zng_logn((long)zng_sc[i]);
    }
    zng_log("\n");
}

/*
 * exec 之前必须先把计数落盘：execve 会替换整个进程映像，计数器随之消失，
 * destructor 也就没机会跑 —— 而"exec 之前花了几个 syscall"恰恰是要测的东西。
 * flush 之后计数归零，新程序从头开始计。
 */
void zng_count_flush(void)
{
    if (!zng_sc_on) return;
    zng_count_emit("pre-exec");
    for (int i = 0; i < 512; i++) zng_sc[i] = 0;
    zng_sc_on = 1;                    /* emit 里被清零过，恢复 */
}

__attribute__((destructor)) static void zng_count_dump(void)
{
    zng_count_emit("exit");
}

/*
 * SIGSYS 诊断：Android 的 app seccomp 若是 SECCOMP_RET_TRAP，
 * 命中时进程收到的 siginfo 里带 si_syscall —— 这是唯一能直接问内核
 * "哪条 syscall 被拦"的手段（dmesg 要 root，strace 不存在）。
 * 若是 KILL_PROCESS，这里什么都打印不出来，那也说明白了。
 */
#if defined(__aarch64__)
#define ZNG_SIG_RT_SIGACTION 134
#define ZNG_SIG_EXIT          93
#else
#define ZNG_SIG_RT_SIGACTION  13
#define ZNG_SIG_EXIT          60
#endif

struct zng_ksigaction {
    void          *handler;
    unsigned long  flags;
    void          *restorer;
    unsigned long  mask;
};
static struct zng_ksigaction g_sigsys_sa;

static void zng_sigsys_handler(int sig, void *sip, void *ctx)
{
    (void)sig; (void)ctx;
    unsigned char *si = (unsigned char *)sip;
    int nr = 0;
    if (si) zng_memcpy(&nr, si + 24, 4);      /* si_syscall */
    zng_log("zng: SIGSYS caught, si_syscall=");
    zng_logn((long)nr);
    zng_log("\n");
    zng_sys1(ZNG_SIG_EXIT, 159);
}

void zng_sigsys_install(void)
{
    g_sigsys_sa.handler  = (void *)zng_sigsys_handler;
    g_sigsys_sa.flags    = 4;            /* SA_SIGINFO */
    g_sigsys_sa.restorer = (void *)0;
    g_sigsys_sa.mask     = 0;
    /* rt_sigaction(SIGSYS=31, &sa, NULL, sizeof(mask)=8) */
    zng_sys4(ZNG_SIG_RT_SIGACTION, 31 /* SIGSYS */, (long)&g_sigsys_sa, 0, 8);
}

void zng_log_init(const struct zng_cfg *c)
{
    g_logfd = 2;
    if (c && c->log_path[0]) {
        long fd = zng_openat(ZNG_AT_FDCWD, c->log_path,
                             ZNG_O_WRONLY | ZNG_O_CREAT | ZNG_O_APPEND |
                             ZNG_O_CLOEXEC, 0644);
        if (!zng_iserr(fd)) g_logfd = (int)fd;
    }
}

void zng_log(const char *s)
{
    if (!s) return;
    zng_write(g_logfd, s, zng_strlen(s));
}

void zng_log2(const char *a, const char *b)
{
    zng_log(a);
    if (b) { zng_log(" "); zng_log(b); }
    zng_log("\n");
}

void zng_logn(long v)
{
    char b[32];
    int i = 30;
    unsigned long u = (unsigned long)v;
    b[31] = 0;
    if (!u) b[i--] = '0';
    while (u && i > 0) { b[i--] = (char)('0' + (u % 10)); u /= 10; }
    zng_log(b + i + 1);
}

/* ================================================================== */
/* argv[0] 分级修复                                                    */
/* ================================================================== */
/*
 * 问题：musl 的 ld.so **没有** --argv0 选项，所以"经加载器中继启动"时，
 * 程序看到的 argv[0] 是 host 路径（/data/.../rootfs/bin/ls），而不是
 * guest 路径（/bin/ls）。busybox 靠 basename 分派 applet，所以功能正常；
 * 但 `echo $0`、ps、错误提示都会露出 host 路径。
 *
 * [A] 的做法：zt_fixup_argv0() 在栈上反向扫描定位 argc，然后原地覆写
 *     argv[0]。问题：依赖未文档化的栈布局；扫描 4096 个槽位；找不到就
 *     **静默 return**，且被 `|| 1` 强制对每个进程执行。
 * [B] 的做法：不修（README 已知限制第 5 条）。
 *
 * 这里的分级策略：
 *   级别 1（默认，安全）：改写 libc 的 __progname (musl) /
 *           program_invocation_name (glibc) 全局指针。这与栈布局无关，
 *           失败可检测，能让 getprogname()、错误输出、ps 等变正确。
 *   级别 2（可选，编译期开启 ZNG_FIX_ARGV0_STACK）：栈回溯覆写真正的
 *           argv[0]。带多重校验，失败时日志可见 —— 绝不静默。
 */
static void fix_progname_global(const char *want)
{
    static char buf[ZNG_PATH_MAX];
    if (!want || !want[0]) return;
    if (zng_strlcpy(buf, want, sizeof buf) < 0) return;

    /* glibc */
    char **pn = (char **)dlsym(ZNG_RTLD_DEFAULT, "program_invocation_name");
    if (pn) *pn = buf;
    char **ps = (char **)dlsym(ZNG_RTLD_DEFAULT, "program_invocation_short_name");
    if (ps) {
        const char *sl = zng_strrchr(buf, '/');
        *ps = (char *)(sl ? sl + 1 : buf);
    }
    /* musl */
    char **mp = (char **)dlsym(ZNG_RTLD_DEFAULT, "__progname");
    if (mp) {
        const char *sl = zng_strrchr(buf, '/');
        *mp = (char *)(sl ? sl + 1 : buf);
    }
    char **mf = (char **)dlsym(ZNG_RTLD_DEFAULT, "__progname_full");
    if (mf) *mf = buf;
}

#ifdef ZNG_FIX_ARGV0_STACK
/*
 * 栈回溯：从 environ 出发找 argv。
 * 布局假设（glibc/musl 当前实现）：
 *     ... [argc][argv[0]]...[argv[argc-1]][NULL][envp[0]]...[NULL] ...
 * 即 envp[-1] == NULL，且 argv[0] 下方 8 字节存放 argc。
 *
 * 与 [A] 的差异：
 *   · 先校验 env0[-1] == NULL（这是最可靠的一条不变式）
 *   · 扫描时同时校验候选 argv[0] 是否为可读字符串
 *   · 目标长度超过原串长度则放弃（不越界写）
 *   · 失败时 debug 日志可见，而不是静默 return
 */
static void fix_argv0_stack(const char *want, char **envp)
{
    size_t wl;
    int found = 0;

    if (!envp || !want || !want[0]) return;
    wl = zng_strlen(want);

    if (envp[-1] != (char *)0) {            /* 不变式不成立：放弃 */
        zng_log("zng: argv0 fix skipped (envp[-1] != NULL)\n");
        return;
    }

    for (long c = 1; c < 4096; c++) {
        char **a0 = envp - 1 - c;
        long stored = *(long *)((char *)a0 - 8);
        if (stored != c) continue;
        if (!a0[0]) break;

        /* 目标必须能放进原字符串的空间内（含 NUL），否则不覆写 */
        if (wl + 1 > zng_strlen(a0[0]) + 1) {
            zng_log("zng: argv0 fix skipped (target longer than original)\n");
            return;
        }
        zng_memcpy(a0[0], want, wl + 1);
        found = 1;
        break;
    }
    if (!found) zng_log("zng: argv0 fix failed (argc signature not found)\n");
}
#else
static void fix_argv0_stack(const char *want, char **envp)
{
    (void)want; (void)envp;   /* 级别 2 未启用：栈布局不可依赖 */
}
#endif

/* ================================================================== */
/* bind 解析（ZNG_BINDS="host\tguest\n..."）                           */
/* ================================================================== */

static void parse_binds(struct zng_cfg *c, const char *val)
{
    const char *p = val;
    while (*p) {
        const char *line = p;
        const char *tab = (const char *)0;
        while (*p && *p != '\n') {
            if (*p == '\t' && !tab) tab = p;
            p++;
        }
        size_t len = (size_t)(p - line);
        if (*p == '\n') p++;
        if (len == 0 || len >= ZNG_PATH_MAX) continue;

        char host[ZNG_PATH_MAX], guest[ZNG_PATH_MAX];
        if (tab) {
            size_t hl = (size_t)(tab - line);
            size_t gl = len - hl - 1;
            if (hl >= sizeof host || gl >= sizeof guest) continue;
            zng_memcpy(host, line, hl);   host[hl] = 0;
            zng_memcpy(guest, tab + 1, gl); guest[gl] = 0;
        } else {
            if (len >= sizeof host) continue;
            zng_memcpy(host, line, len);  host[len] = 0;
            zng_strcpy(guest, host);
        }

        /*
         * bind 添加失败必须显式报告：静默丢弃会让"某个目录突然能看到
         * host 内容"或反之，是极难排查的故障（[A] 就是静默丢弃的）。
         */
        int r = zng_cfg_bind_add(c, host, guest);
        if (r < 0) {
            zng_log2("zng: bind add failed (visible failure):", host);
            zng_logn(r);
            zng_log("\n");
        }
    }
}

/* ================================================================== */
/* 构造                                                                */
/* ================================================================== */

__attribute__((constructor))
static void zng_ctor(void)
{
    const char *root = getenv("ZNG_ROOT");
    if (!root || root[0] != '/') {
        /* 惰性：未配置 rootfs，shim 完全不介入 */
        g_ready = 0;
        return;
    }

    if (zng_cfg_init(&g_cfg) < 0) return;

    if (zng_strlcpy(g_cfg.root, root, sizeof g_cfg.root) < 0) {
        zng_cfg_free(&g_cfg);
        return;
    }
    /* 去掉尾部斜杠，保持与 bind 一致的处理 */
    size_t l = zng_strlen(g_cfg.root);
    while (l > 1 && g_cfg.root[l - 1] == '/') g_cfg.root[--l] = 0;
    g_cfg.root_len = l;

    {
        const char *v = getenv("ZNG_PRELOAD");
        if (v && v[0]) zng_strlcpy(g_cfg.self, v, sizeof g_cfg.self);
    }
    {
        const char *v = getenv("ZNG_LOG");
        if (v && v[0]) zng_strlcpy(g_cfg.log_path, v, sizeof g_cfg.log_path);
    }
    {
        const char *v = getenv("ZNG_FAKE_ROOT");
        g_cfg.fake_root = (v && v[0] == '1');
    }
    {
        {
        const char *vc = getenv("ZNG_COUNT");
        zng_sc_on = (vc && vc[0] && vc[0] != '0') ? 1 : 0;
    }
    const char *v = getenv("ZNG_DEBUG");
        g_cfg.debug = (v && v[0] == '1');
    }
    {
        const char *v = getenv("ZNG_BINDS");
        if (v && v[0]) parse_binds(&g_cfg, v);
    }

    /*
     * 检测 libc 种类。
     *
     * glibc rootfs 的 /usr/lib 里是**编译期**用的 GNU ld script（libm.so
     * 之类的 ASCII 文本），若参与库搜索会让 ld.so 选中脚本报
     * "bad ELF magic"。因此库搜索路径必须按 libc 区分（见 zng_libpath）。
     * 判据：rootfs 内是否存在 glibc 的动态链接器。
     */
    {
        char p[ZNG_PATH_MAX];
        long o = zng_strlcpy(p, g_cfg.root, sizeof p);
        const char *tail = "/lib/ld-linux-aarch64.so.1";
        size_t tl = zng_strlen(tail);
        if (o >= 0 && (size_t)o + tl + 1 <= sizeof p) {
            zng_memcpy(p + o, tail, tl + 1);
            g_cfg.is_glibc =
                !zng_iserr(zng_faccessat(ZNG_AT_FDCWD, p, ZNG_F_OK, 0));
        }
    }

    zng_log_init(&g_cfg);
    zng_sigsys_install();     /* 只为了把"被 seccomp 拦的 syscall 号"打出来 */
    zng_resolver_init(&g_cfg);

    if (g_cfg.debug) {
        zng_log("zng: active root=");
        zng_log(g_cfg.root);
        zng_log(" binds=");
        zng_logn(g_cfg.nbinds);
        zng_log(" libc=");
        zng_log(g_cfg.is_glibc ? "glibc" : "musl");
        zng_log("\n");
    }

    g_ready = 1;

    /* argv[0]：仅在 exec 中继场景（ZNG_ARGV0 由父进程注入）下修复 */
    {
        const char *want = getenv("ZNG_ARGV0");
        if (want && want[0]) {
            fix_progname_global(want);          /* 级别 1：始终执行 */
            fix_argv0_stack(want, environ);     /* 级别 2：按编译开关 */
        }
    }
}
