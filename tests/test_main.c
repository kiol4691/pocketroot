/* SPDX-License-Identifier: MIT */
/*
 * test_main.c — zng 核心逻辑单元测试（x86_64，真 libc，可配 ASan）
 *
 * 为什么要这个东西：
 *   [A] 核心算法（路径翻译、ELF 探测、env 构造）与 syscall/全局状态耦合，
 *       只能在装好 rootfs 的机器上"跑一遍看看"，异常路径从未被覆盖 ——
 *       结果就是 find_component 的格式串误用、nenv 泄漏、bind 静默失效
 *       这些 bug 全部藏在 happy path 之外。
 *   [B] 只有 12 项 qemu 端到端测试，且 exec 链在 qemu 上根本测不了。
 *
 * 本文件在 x86_64 上直接测**纯逻辑**，无需 Android、无需 rootfs、无需 qemu。
 * 配合 -fsanitize=address,undefined 可以抓出：
 *   · 越界写（路径缓冲）
 *   · use-after-free / double-free（env 数组归属混淆 —— A 就漏 free 了 nenv）
 *   · 未对齐访问、有符号溢出
 */
#define ZNG_HOST_TEST 1

#include "../shim/zng.h"
#include "../shim/zng_sys.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>   /* 仅用于校验 syscall 号表 */

static int checks, fails;

#define CHECK(cond) do {                                                    \
    checks++;                                                               \
    if (!(cond)) {                                                          \
        fails++;                                                            \
        printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);            \
    }                                                                       \
} while (0)

#define CHECK_STR(got, want) do {                                           \
    checks++;                                                               \
    const char *g_ = (got), *w_ = (want);                                   \
    if (!g_ || strcmp(g_, w_) != 0) {                                       \
        fails++;                                                            \
        printf("  FAIL %s:%d\n    got : %s\n    want: %s\n",                \
               __FILE__, __LINE__, g_ ? g_ : "(null)", w_);                 \
    }                                                                       \
} while (0)

#define SECTION(name) printf("== %s ==\n", name)

/* ------------------------------------------------------------------ */
/* syscall 号表校验                                                    */
/* ------------------------------------------------------------------ */
/*
 * [A] zsuper.c 的 _Static_assert 只覆盖 x86_64，arm64 号表从未校验。
 *     这里把校验放进测试：x86_64 上能与 libc 常量对照；arm64 号表无法在
 *     x86_64 上对照，但至少保证有人记得这件事（见 tests/README）。
 */
#if defined(__x86_64__)
#define ZNG_ASSERT_NR(name) _Static_assert((long)SYS_##name == (long)ZNG_NR_##name, \
                                           "syscall nr mismatch: " #name)
ZNG_ASSERT_NR(read);
ZNG_ASSERT_NR(write);
ZNG_ASSERT_NR(openat);
ZNG_ASSERT_NR(close);
ZNG_ASSERT_NR(lseek);
ZNG_ASSERT_NR(newfstatat);
ZNG_ASSERT_NR(fstat);
ZNG_ASSERT_NR(readlinkat);
ZNG_ASSERT_NR(faccessat);
ZNG_ASSERT_NR(getcwd);
ZNG_ASSERT_NR(chdir);
ZNG_ASSERT_NR(fchdir);
ZNG_ASSERT_NR(dup3);
ZNG_ASSERT_NR(pipe2);
ZNG_ASSERT_NR(getdents64);
ZNG_ASSERT_NR(execve);
ZNG_ASSERT_NR(exit_group);
ZNG_ASSERT_NR(unlinkat);
ZNG_ASSERT_NR(mkdirat);
ZNG_ASSERT_NR(mknodat);
ZNG_ASSERT_NR(renameat);
ZNG_ASSERT_NR(symlinkat);
ZNG_ASSERT_NR(linkat);
ZNG_ASSERT_NR(fchmodat);
ZNG_ASSERT_NR(fchownat);
ZNG_ASSERT_NR(utimensat);
ZNG_ASSERT_NR(truncate);
ZNG_ASSERT_NR(ftruncate);
ZNG_ASSERT_NR(getpid);
ZNG_ASSERT_NR(getuid);
ZNG_ASSERT_NR(geteuid);
ZNG_ASSERT_NR(getgid);
ZNG_ASSERT_NR(getegid);
ZNG_ASSERT_NR(ioctl);
ZNG_ASSERT_NR(fcntl);
ZNG_ASSERT_NR(prctl);
#endif

/* ------------------------------------------------------------------ */
/* 辅助                                                                */
/* ------------------------------------------------------------------ */

static void put16(unsigned char *p, uint16_t v)
{ for (int i = 0; i < 2; i++) p[i] = (unsigned char)(v >> (8 * i)); }
static void put32(unsigned char *p, uint32_t v)
{ for (int i = 0; i < 4; i++) p[i] = (unsigned char)(v >> (8 * i)); }
static void put64(unsigned char *p, uint64_t v)
{ for (int i = 0; i < 8; i++) p[i] = (unsigned char)(v >> (8 * i)); }

/* 造一个最小合法 ELF64：phdr[0]=PT_LOAD, phdr[1]=PT_INTERP */
static size_t mkelf(unsigned char *b, size_t cap, const char *interp, int nph)
{
    if (cap < 512) return 0;
    memset(b, 0, cap);
    b[0] = 0x7f; b[1] = 'E'; b[2] = 'L'; b[3] = 'F';
    b[4] = 2;                       /* ELFCLASS64 */
    b[5] = 1;                       /* ELFDATA2LSB */
    b[6] = 1;
    put16(b + 16, 3);               /* ET_DYN */
    put16(b + 18, 183);             /* EM_AARCH64 */
    put32(b + 20, 1);
    put64(b + 0x20, 64);            /* e_phoff */
    put16(b + 52, 64);              /* e_ehsize */
    put16(b + 54, 56);              /* e_phentsize */
    put16(b + 56, (uint16_t)nph);   /* e_phnum */
    put16(b + 58, 64);              /* e_shentsize */

    if (nph >= 1) {                 /* PT_LOAD */
        put32(b + 64 + 0, 1);
        put64(b + 64 + 8, 0);
        put64(b + 64 + 32, 0x1000);
    }
    if (nph >= 2 && interp) {       /* PT_INTERP */
        size_t stroff = 64 + 56 * 2;
        size_t sl = strlen(interp) + 1;
        put32(b + 64 + 56 + 0, 3);
        put64(b + 64 + 56 + 8, stroff);
        put64(b + 64 + 56 + 32, sl);
        if (stroff + sl > cap) return 0;
        memcpy(b + stroff, interp, sl);
        return stroff + sl;
    }
    return 64 + 56 * (size_t)nph;
}

static int mkcfg(struct zng_cfg *c, const char *root)
{
    if (zng_cfg_init(c) < 0) return -1;
    size_t l = strlen(root);
    memcpy(c->root, root, l + 1);
    c->root_len = l;
    return 0;
}

/* ------------------------------------------------------------------ */
/* 路径视图                                                            */
/* ------------------------------------------------------------------ */

static void test_pv(void)
{
    SECTION("pathview");
    struct zng_pv v, c;

    CHECK(zng_pv_from("/a/b/c", &v) == 0);
    CHECK(v.n == 3);

    CHECK(zng_pv_from("///a//b///", &v) == 0);   /* 空组件被压缩 */
    CHECK(v.n == 2);

    CHECK(zng_pv_from("/a/./b", &v) == 0);       /* "." 被跳过 */
    CHECK(v.n == 2);

    CHECK(zng_pv_from("/a/../b", &v) == 0);      /* ".." 保留（关键） */
    CHECK(v.n == 3);
    CHECK(zng_pv_is_dotdot(&v, 1) == 1);

    CHECK(zng_pv_clean(&v, &c) == 0);            /* cleaned: [b] */
    CHECK(c.n == 1);

    /* 前导 ".." 在 clean 时被 clamp，不上升到根之上 */
    CHECK(zng_pv_from("/../../x", &v) == 0);
    CHECK(zng_pv_clean(&v, &c) == 0);
    CHECK(c.n == 1);

    /* 组件数上限：A 用 128，这里 64 —— 超限必须报错而不是截断 */
    char big[512];
    big[0] = '/';
    for (int i = 0; i < 100; i++) { big[1 + i * 2] = 'a'; big[2 + i * 2] = '/'; }
    big[201] = 0;
    CHECK(zng_pv_from(big, &v) == -ZNG_ENAMETOOLONG);

    /* 前缀匹配是组件级的，不是字符串前缀 */
    CHECK(zng_pv_from("/proc/self", &v) == 0);
    CHECK(zng_pv_prefix(&v, 0, "/proc") == 1);
    CHECK(zng_pv_prefix(&v, 0, "/pro") == 0);      /* 关键：不能匹配半个组件 */
    CHECK(zng_prefix_comps("/proc") == 1);
    CHECK(zng_prefix_comps("/") == 0);
}

/* ------------------------------------------------------------------ */
/* 翻译                                                                */
/* ------------------------------------------------------------------ */

static void test_translate(void)
{
    SECTION("translate / untranslate");
    struct zng_cfg c;
    char out[ZNG_PATH_MAX];

    CHECK(mkcfg(&c, "/data/rootfs") == 0);
    CHECK(zng_cfg_bind_add(&c, "/proc", "/proc") == 0);
    CHECK(zng_cfg_bind_add(&c, "/host/x", "/mnt/x") == 0);

    /* 基本重定向 */
    CHECK(zng_translate(&c, "/bin/ls", out, sizeof out) == 1);
    CHECK_STR(out, "/data/rootfs/bin/ls");

    /* 根 */
    CHECK(zng_translate(&c, "/", out, sizeof out) == 1);
    CHECK_STR(out, "/data/rootfs");

    /* bind：guest -> host，路径不变 */
    CHECK(zng_translate(&c, "/proc/1/status", out, sizeof out) == 1);
    CHECK_STR(out, "/proc/1/status");

    /* bind：不同路径 */
    CHECK(zng_translate(&c, "/mnt/x/f", out, sizeof out) == 1);
    CHECK_STR(out, "/host/x/f");

    /* 幂等：已带 rootfs 前缀则不再叠加 */
    CHECK(zng_translate(&c, "/data/rootfs/bin/ls", out, sizeof out) == 0);
    CHECK_STR(out, "/data/rootfs/bin/ls");

    /* 前缀相似但不成组件的，必须照样重定向（不是幂等） */
    CHECK(zng_translate(&c, "/data/rootfsXX/y", out, sizeof out) == 1);
    CHECK_STR(out, "/data/rootfs/data/rootfsXX/y");

    /* 相对路径原样返回 */
    CHECK(zng_translate(&c, "rel/path", out, sizeof out) == 0);
    CHECK_STR(out, "rel/path");

    /* 中间的 ".." 保留给内核解析（raw 视图） */
    CHECK(zng_translate(&c, "/a/../b", out, sizeof out) == 1);
    CHECK_STR(out, "/data/rootfs/a/../b");

    /* 前导 ".." 被 clamp（chroot 语义） */
    CHECK(zng_translate(&c, "/../a", out, sizeof out) == 1);
    CHECK_STR(out, "/data/rootfs/a");

    /*
     * bind 边界处的 ".." —— 这是**刻意保留**的行为，不要"修好"它。
     *
     * cleaned("/proc/../bin") == "/bin"，已经不再匹配 /proc 这个 bind，
     * 于是落到 rootfs 分支，而该分支使用 RAW 视图（保留 ".."）：
     *     /proc/../bin  ->  /data/rootfs/proc/../bin
     *
     * 为什么不在用户态弹出 ".."：若 /bin 是指向 /usr/bin 的符号链接，
     * 那么 /bin/../etc 的真实语义是 /usr/etc（先解析链接，再回上一级）。
     * 在用户态提前弹出 ".." 会得到 /etc —— 那是错的。
     * 保留 ".." 交给内核 / openat2(RESOLVE_IN_ROOT) 解析，才能拿到符号
     * 链接**之后**的真实语义。A 的 zt-paths.c 是同样的设计，此处刻意继承。
     */
    CHECK(zng_translate(&c, "/proc/../bin", out, sizeof out) == 1);
    CHECK_STR(out, "/data/rootfs/proc/../bin");

    /* 仍在 bind 内部的 ".."：cleaned 后仍匹配 bind，正常走 bind 分支 */
    CHECK(zng_translate(&c, "/proc/../proc/1", out, sizeof out) == 1);
    CHECK_STR(out, "/proc/1");

    /*
     * 缓冲不足必须报错，而不是"原样透传"。
     * [B] 在这里透传到 host —— 等于把隔离漏洞伪装成一次成功调用。
     * [A] 在 zt_binds_serialize 里静默丢弃全部 bind。
     */
    CHECK(zng_translate(&c, "/bin/ls", out, 8) == -ZNG_ENAMETOOLONG);

    /* 未配置 root 时惰性（不改写） */
    struct zng_cfg c2;
    CHECK(zng_cfg_init(&c2) == 0);
    CHECK(zng_translate(&c2, "/bin/ls", out, sizeof out) == 0);
    CHECK_STR(out, "/bin/ls");
    zng_cfg_free(&c2);

    /* ---- untranslate ---- */
    CHECK(zng_untranslate(&c, "/data/rootfs/bin/ls", out, sizeof out) == 1);
    CHECK_STR(out, "/bin/ls");

    CHECK(zng_untranslate(&c, "/data/rootfs", out, sizeof out) == 1);
    CHECK_STR(out, "/");

    CHECK(zng_untranslate(&c, "/proc/1/status", out, sizeof out) == 1);
    CHECK_STR(out, "/proc/1/status");

    /* 不在沙箱内：原样 */
    CHECK(zng_untranslate(&c, "/system/lib", out, sizeof out) == 0);
    CHECK_STR(out, "/system/lib");

    CHECK(zng_under_root(&c, "/data/rootfs/x") == 1);
    CHECK(zng_under_root(&c, "/data/rootfsXX") == 0);   /* 组件边界 */

    zng_cfg_free(&c);
}

static void test_bind_limits(void)
{
    SECTION("bind 上限（fail-visible）");
    struct zng_cfg c;
    CHECK(zng_cfg_init(&c) == 0);

    /* 初始 cap=8，加到 20 会触发扩容 —— 必须全部成功且内容无损 */
    char h[64], g[64];
    for (int i = 0; i < 20; i++) {
        snprintf(h, sizeof h, "/host/%d", i);
        snprintf(g, sizeof g, "/guest/%d", i);
        CHECK(zng_cfg_bind_add(&c, h, g) == 0);
    }
    CHECK(c.nbinds == 20);
    CHECK_STR(c.binds[19].host, "/host/19");

    /* 超过 ZNG_MAX_BINDS 必须返回 -ENOSPC，而不是静默丢弃 */
    for (int i = 20; i < ZNG_MAX_BINDS; i++) {
        snprintf(h, sizeof h, "/host/%d", i);
        snprintf(g, sizeof g, "/guest/%d", i);
        CHECK(zng_cfg_bind_add(&c, h, g) == 0);
    }
    CHECK(zng_cfg_bind_add(&c, "/host/x", "/guest/x") == -ZNG_ENOSPC);
    CHECK(c.nbinds == ZNG_MAX_BINDS);

    /* 尾部斜杠归一化 */
    struct zng_cfg c2;
    CHECK(zng_cfg_init(&c2) == 0);
    CHECK(zng_cfg_bind_add(&c2, "/host/x/", "/guest/y/") == 0);
    CHECK_STR(c2.binds[0].host, "/host/x");
    CHECK_STR(c2.binds[0].guest, "/guest/y");
    CHECK(zng_cfg_bind_add(&c2, "", "/g") == -ZNG_EINVAL);
    zng_cfg_free(&c2);

    zng_cfg_free(&c);
}

/* ------------------------------------------------------------------ */
/* ELF                                                                 */
/* ------------------------------------------------------------------ */

static void test_elf(void)
{
    SECTION("ELF 解析");
    unsigned char buf[4096];
    char interp[256];
    size_t n;

    /* 动态链接：含 PT_INTERP */
    n = mkelf(buf, sizeof buf, "/lib/ld-musl-aarch64.so.1", 2);
    CHECK(n > 0);

    long span = zng_elf_span(buf, 64);
    CHECK(span > 0);
    CHECK((size_t)span <= n);

    CHECK(zng_elf_interp(buf, n, interp, sizeof interp) == ZNG_ELF_DYNAMIC);
    CHECK_STR(interp, "/lib/ld-musl-aarch64.so.1");

    /* glibc 解释器同样能识别（这是 B 完全做不到的：它硬编码 musl 路径） */
    n = mkelf(buf, sizeof buf, "/lib64/ld-linux-x86-64.so.2", 2);
    CHECK(zng_elf_interp(buf, n, interp, sizeof interp) == ZNG_ELF_DYNAMIC);
    CHECK_STR(interp, "/lib64/ld-linux-x86-64.so.2");

    /* 静态：无 phdr */
    n = mkelf(buf, sizeof buf, NULL, 0);
    CHECK(zng_elf_interp(buf, n, interp, sizeof interp) == ZNG_ELF_STATIC);

    /* 动态但无 PT_INTERP（异常但可能） */
    n = mkelf(buf, sizeof buf, NULL, 1);
    CHECK(zng_elf_interp(buf, n, interp, sizeof interp) == ZNG_ELF_STATIC);

    /* 非 ELF */
    memcpy(buf, "#!/bin/sh\n", 10);
    CHECK(zng_elf_span(buf, 64) == -ZNG_ENOEXEC);

    /* 32 位 ELF：明确拒绝，不猜 */
    n = mkelf(buf, sizeof buf, "/lib/ld.so", 2);
    buf[4] = 1;                                  /* ELFCLASS32 */
    CHECK(zng_elf_span(buf, 64) == -ZNG_ENOEXEC);

    /* 畸形 phentsize */
    n = mkelf(buf, sizeof buf, "/lib/ld.so", 2);
    put16(buf + 54, 32);
    CHECK(zng_elf_span(buf, 64) == -ZNG_ENOEXEC);

    /* buffer 不足：必须报错而不是越界读 */
    n = mkelf(buf, sizeof buf, "/lib/ld-musl-aarch64.so.1", 2);
    CHECK(zng_elf_interp(buf, 64, interp, sizeof interp) == -ZNG_EIO);

    /* interp 长度超过输出缓冲 */
    char big[600];
    memset(big, 'a', sizeof big - 1);
    big[0] = '/';
    big[sizeof big - 1] = 0;
    n = mkelf(buf, sizeof buf, big, 2);
    CHECK(zng_elf_interp(buf, n, interp, sizeof interp) == -ZNG_ENAMETOOLONG);
}

/* ------------------------------------------------------------------ */
/* env（fixenv）—— B 的 0.1.8 bug 回归测试                             */
/* ------------------------------------------------------------------ */

static void test_env(void)
{
    SECTION("env 构造");

    struct zng_cfg c;
    CHECK(mkcfg(&c, "/rootfs") == 0);
    strcpy(c.self, "/data/app/lib/libzng.so");

    /*
     * 回归：envp == NULL（等价 env -i / clearenv 之后）。
     * [B 0.1.8 前的 bug] 特判分支返回未构造的静态空串 -> LD_PRELOAD=""
     *   -> ldso 静默忽略 -> 子进程裸奔 -> SIGSYS(159)。
     * 这里必须仍然注入完整三件套。
     */
    char **nv = zng_env_build(&c, NULL);
    CHECK(nv != NULL);
    if (nv) {
        int have_preload = 0, have_root = 0, have_zpre = 0, have_path = 0;
        for (int i = 0; nv[i]; i++) {
            if (strncmp(nv[i], "LD_PRELOAD=", 11) == 0) {
                have_preload = 1;
                CHECK_STR(nv[i], "LD_PRELOAD=/data/app/lib/libzng.so");
            }
            if (strncmp(nv[i], "ZNG_ROOT=", 9) == 0) have_root = 1;
            if (strncmp(nv[i], "ZNG_PRELOAD=", 12) == 0) have_zpre = 1;
            if (strncmp(nv[i], "PATH=", 5) == 0) have_path = 1;
        }
        CHECK(have_preload);
        CHECK(have_root);
        CHECK(have_zpre);
        CHECK(have_path);
        zng_env_free(nv);           /* ASan：误 free 借来指针会在这里炸 */
    }

    /* 恶意/陈旧 LD_PRELOAD 必须被我们的覆盖，且只出现一次 */
    char *env1[] = { (char *)"LD_PRELOAD=/evil.so",
                     (char *)"ZNG_ROOT=/fake",
                     (char *)"PATH=/custom",
                     (char *)"MYVAR=keepme",
                     NULL };
    nv = zng_env_build(&c, env1);
    CHECK(nv != NULL);
    if (nv) {
        int npre = 0, nroot = 0, npath = 0, keep = 0;
        for (int i = 0; nv[i]; i++) {
            if (strncmp(nv[i], "LD_PRELOAD=", 11) == 0) {
                npre++;
                CHECK_STR(nv[i], "LD_PRELOAD=/data/app/lib/libzng.so");
                CHECK(strstr(nv[i], "evil") == NULL);
            }
            if (strncmp(nv[i], "ZNG_ROOT=", 9) == 0) {
                nroot++;
                CHECK_STR(nv[i], "ZNG_ROOT=/rootfs");
            }
            if (strncmp(nv[i], "PATH=", 5) == 0) {
                npath++;
                CHECK_STR(nv[i], "PATH=/custom");   /* 用户 PATH 被保留 */
            }
            if (strcmp(nv[i], "MYVAR=keepme") == 0) keep = 1;
        }
        CHECK(npre == 1);
        CHECK(nroot == 1);
        CHECK(npath == 1);
        CHECK(keep == 1);           /* 无关变量原样保留 */
        zng_env_free(nv);
    }

    /* LD_LIBRARY_PATH：rootfs 库路径前置，用户值保留在后 */
    char *env2[] = { (char *)"LD_LIBRARY_PATH=/opt/mine", NULL };
    nv = zng_env_build(&c, env2);
    if (nv) {
        for (int i = 0; nv[i]; i++) {
            if (strncmp(nv[i], "LD_LIBRARY_PATH=", 16) == 0) {
                CHECK(strstr(nv[i], "/rootfs/lib") != NULL);
                CHECK(strstr(nv[i], "/opt/mine") != NULL);
                /* rootfs 必须在前，确保 rootfs 的库优先于 host 的 */
                CHECK(strstr(nv[i], "/rootfs/lib") < strstr(nv[i], "/opt/mine"));
            }
        }
        zng_env_free(nv);
    }

    zng_cfg_free(&c);
}

/* ------------------------------------------------------------------ */
/* exec 计划                                                           */
/* ------------------------------------------------------------------ */

static void test_plan(void)
{
    SECTION("exec 计划构造");

    struct zng_cfg c;
    CHECK(mkcfg(&c, "/rootfs") == 0);
    strcpy(c.self, "/data/app/lib/libzng.so");
    CHECK(zng_cfg_bind_add(&c, "/proc", "/proc") == 0);

    /* ---- musl：ldso PROG args... ---- */
    char *av[] = { (char *)"/bin/ls", (char *)"-l", NULL };
    char *ev[] = { (char *)"A=1", NULL };
    struct zng_plan p;

    CHECK(zng_plan_build(&c, "/rootfs/bin/ls",
                         "/rootfs/lib/ld-musl-aarch64.so.1", av, ev, &p) == 0);
    CHECK(p.ld_kind == ZNG_LD_MUSL);
    CHECK_STR(p.argv[0], "/rootfs/lib/ld-musl-aarch64.so.1");
    CHECK_STR(p.argv[1], "/rootfs/bin/ls");
    CHECK_STR(p.argv[2], "-l");
    CHECK(p.argv[3] == NULL);
    /* musl 无 --argv0：期望的 argv0 经 ZNG_ARGV0 传给子进程 ctor */
    {
        int found = 0;
        for (int i = 0; p.envp[i]; i++)
            if (strncmp(p.envp[i], "ZNG_ARGV0=", 10) == 0) {
                found = 1;
                CHECK_STR(p.envp[i], "ZNG_ARGV0=/bin/ls");
            }
        CHECK(found);
    }
    zng_plan_free(&p);              /* ASan：验证 argv/env 的归属释放正确 */
    CHECK(p.argv == NULL);
    CHECK(p.envp == NULL);

    /*
     * ---- glibc：ld.so --argv0 A0 --library-path LIBS PROG args... ----
     * 这是 B 完全不支持、A 支持但从未在 Android 上验证过的路径。
     */
    CHECK(zng_plan_build(&c, "/rootfs/bin/ls",
                         "/rootfs/lib64/ld-linux-x86-64.so.2", av, ev, &p) == 0);
    CHECK(p.ld_kind == ZNG_LD_GLIBC);
    CHECK_STR(p.argv[0], "/rootfs/lib64/ld-linux-x86-64.so.2");
    CHECK_STR(p.argv[1], "--argv0");
    CHECK_STR(p.argv[2], "/bin/ls");      /* 用户看到的真实 argv[0] */
    CHECK_STR(p.argv[3], "--library-path");
    CHECK(strstr(p.argv[4], "/rootfs/lib") != NULL);
    CHECK_STR(p.argv[5], "/rootfs/bin/ls");
    CHECK_STR(p.argv[6], "-l");
    CHECK(p.argv[7] == NULL);
    zng_plan_free(&p);

    /* 未知加载器：按 musl 协议保守处理（参数更少，不会误传 --argv0） */
    CHECK(zng_plan_build(&c, "/rootfs/bin/ls", "/weird/ld-thing", av, ev, &p) == 0);
    CHECK(p.ld_kind == ZNG_LD_OTHER);
    CHECK_STR(p.argv[0], "/weird/ld-thing");
    CHECK_STR(p.argv[1], "/rootfs/bin/ls");
    zng_plan_free(&p);

    /* 参数校验：缺 prog/interp 必须失败，不能构造出残缺 argv */
    CHECK(zng_plan_build(&c, NULL, "/rootfs/lib/ld-musl", av, ev, &p) == -ZNG_EINVAL);
    CHECK(zng_plan_build(&c, "/rootfs/bin/ls", NULL, av, ev, &p) == -ZNG_EINVAL);

    zng_cfg_free(&c);
}

/* ------------------------------------------------------------------ */

int main(void)
{
    printf("zng core unit tests\n\n");
    test_pv();
    test_translate();
    test_bind_limits();
    test_elf();
    test_env();
    test_plan();

    printf("\n---- %d checks, %d failures ----\n", checks, fails);
    return fails ? 1 : 0;
}
