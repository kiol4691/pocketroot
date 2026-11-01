/* SPDX-License-Identifier: MIT */
/*
 * zng_core.c — 纯逻辑核心：配置、路径视图、翻译、ELF 解析、exec 计划
 *
 * 本文件**不发起任何 syscall**，只做内存计算。因此它可以：
 *   - 在 x86_64 上用普通 libc 编译并做单元测试（tests/test_main.c）
 *   - 被 fuzz
 *   - 被复用进其他载体（App、CLI 工具、桌面版）
 *
 * [A] 把 ELF 解析和 fd 读取耦合（zt_elf_probe_fd），路径翻译和全局 zt_g
 *     耦合 —— 导致这两块核心逻辑根本无法脱离真机验证，只能在设备上"试"。
 * [B] 全部逻辑散在 hooks 里，没有任何一层是可单独测的。
 */
#include "zng.h"

/*
 * 可替换分配器。
 * 正式构建（freestanding .so）：解析宿主 libc 的 malloc/free —— shim 不链接
 *   libc，符号在加载时解析，因此同一个 .so 能注入 musl 也能注入 glibc。
 * 单元测试（ZNG_HOST_TEST）：直接用宿主 libc 的 malloc/free，从而让整个
 *   核心逻辑可以在 x86_64 上脱离 Android 跑起来 —— 这正是 A/B 都做不到的事。
 */
#ifdef ZNG_HOST_TEST
#include <stdlib.h>
static void *zng_alloc(unsigned long n) { return malloc((size_t)n); }
static void  zng_free(void *p)          { if (p) free(p); }
#else
extern void *malloc(unsigned long);
extern void  free(void *);
static void *zng_alloc(unsigned long n) { return malloc(n); }
static void  zng_free(void *p)          { if (p) free(p); }
#endif

/* ================================================================== */
/* 配置                                                                */
/* ================================================================== */

static char *zng_dup(const char *s)
{
    size_t l = zng_strlen(s);
    char *p = (char *)zng_alloc(l + 1);
    if (!p) return (char *)0;
    zng_memcpy(p, s, l + 1);
    return p;
}

/* 对外分配器入口（zng_run.c / hooks 使用） */
void *zng_alloc_bytes(unsigned long n) { return zng_alloc(n); }
void  zng_free_bytes(void *p)          { zng_free(p); }

static const char *zng_strstr_local(const char *h, const char *n)
{
    size_t nl = zng_strlen(n);
    if (!h) return (const char *)0;
    if (nl == 0) return h;
    for (; *h; h++)
        if (*h == *n && zng_strncmp(h, n, nl) == 0) return h;
    return (const char *)0;
}

int zng_cfg_init(struct zng_cfg *c)
{
    if (!c) return -ZNG_EINVAL;
    zng_memset(c, 0, sizeof *c);
    c->cap = 8;
    /* [A] zt_g 里 binds[64] 每个含两个 char[4096] —— 约 524KB 全局 BSS，
     *     每个被注入的进程都要背这份开销，哪怕只用 1 个 bind。
     *     => 这里按需分配：初始 8 个槽，每个路径按实际长度 strdup。 */
    c->binds = (struct zng_bind *)zng_alloc(sizeof(struct zng_bind) * (unsigned long)c->cap);
    if (!c->binds) return -ZNG_ENOMEM;
    return 0;
}

void zng_cfg_free(struct zng_cfg *c)
{
    if (!c) return;
    for (int i = 0; i < c->nbinds; i++) {
        zng_free(c->binds[i].host);
        zng_free(c->binds[i].guest);
    }
    zng_free(c->binds);
    c->binds = (struct zng_bind *)0;
    c->nbinds = c->cap = 0;
}

/* 去掉尾部斜杠（保留根 "/"） */
static size_t zng_trim(char *s)
{
    size_t l = zng_strlen(s);
    while (l > 1 && s[l - 1] == '/') s[--l] = 0;
    return l;
}

int zng_cfg_bind_add(struct zng_cfg *c, const char *host, const char *guest)
{
    if (!c || !host || !guest || !host[0] || !guest[0]) return -ZNG_EINVAL;

    /* [A] zt_bind_add 在超限后返回 -1，但 zroot.c 的调用点只 die("too many
     *     binds")；zt_env_overlay 里序列化溢出时却**静默丢弃全部 bind**。
     *     => 这里统一返回 -ENOSPC，让调用方必须处理（fail-visible）。 */
    if (c->nbinds >= ZNG_MAX_BINDS) return -ZNG_ENOSPC;

    if (c->nbinds + 1 > c->cap) {
        /* cap 可能是 0（cfg 被 memset 过、没走 cfg_init）：
         * 0*2 仍是 0，会导致 malloc(0) + 越界 memcpy。基准程序
         * 第一次跑就踩到了，这里兜底成初始容量。 */
        int nc = c->cap > 0 ? c->cap * 2 : 8;
        if (nc > ZNG_MAX_BINDS) nc = ZNG_MAX_BINDS;
        struct zng_bind *nb =
            (struct zng_bind *)zng_alloc(sizeof(struct zng_bind) * (unsigned long)nc);
        if (!nb) return -ZNG_ENOMEM;
        zng_memcpy(nb, c->binds,
                   sizeof(struct zng_bind) * (unsigned long)c->nbinds);
        zng_free(c->binds);
        c->binds = nb;
        c->cap = nc;
    }

    struct zng_bind *b = &c->binds[c->nbinds];
    b->host = zng_dup(host);
    b->guest = zng_dup(guest);
    if (!b->host || !b->guest) {
        zng_free(b->host);
        zng_free(b->guest);
        b->host = b->guest = (char *)0;
        return -ZNG_ENOMEM;
    }
    b->host_len = zng_trim(b->host);
    b->guest_len = zng_trim(b->guest);
    if (b->host_len == 0 || b->guest_len == 0) {
        zng_free(b->host);
        zng_free(b->guest);
        return -ZNG_EINVAL;
    }
    c->nbinds++;
    return 0;
}

/* ================================================================== */
/* 路径视图                                                            */
/* ================================================================== */

int zng_pv_from(const char *p, struct zng_pv *v)
{
    if (!p || !v) return -ZNG_EINVAL;
    v->s = p;
    v->n = 0;
    size_t i = 0;
    while (p[i]) {
        while (p[i] == '/') i++;
        size_t st = i;
        while (p[i] && p[i] != '/') i++;
        size_t l = i - st;
        if (l == 0) break;
        if (l == 1 && p[st] == '.') continue;          /* 跳过 "." */
        if (v->n >= ZNG_MAX_COMPS) return -ZNG_ENAMETOOLONG;
        v->off[v->n] = st;
        v->len[v->n] = l;
        v->n++;
    }
    return 0;
}

int zng_pv_is_dotdot(const struct zng_pv *v, int k)
{
    return v->len[k] == 2 && v->s[v->off[k]] == '.' && v->s[v->off[k] + 1] == '.';
}

int zng_pv_clean(const struct zng_pv *src, struct zng_pv *dst)
{
    int stack[ZNG_MAX_COMPS];
    int sp = 0;
    if (!src || !dst) return -ZNG_EINVAL;
    for (int k = 0; k < src->n; k++) {
        if (zng_pv_is_dotdot(src, k)) {
            if (sp > 0) sp--;                 /* 已在根：clamp，不上升 */
        } else {
            if (sp >= ZNG_MAX_COMPS) return -ZNG_ENAMETOOLONG;
            stack[sp++] = k;
        }
    }
    dst->s = src->s;
    for (int k = 0; k < sp; k++) {
        dst->off[k] = src->off[stack[k]];
        dst->len[k] = src->len[stack[k]];
    }
    dst->n = sp;
    return 0;
}

int zng_pv_prefix(const struct zng_pv *v, int from, const char *prefix)
{
    if (!v || !prefix) return 0;
    size_t plen = zng_strlen(prefix);
    if (plen == 0) return 0;
    if (plen == 1 && prefix[0] == '/') return 1;       /* "/" 匹配一切 */

    size_t i = 0;
    int k = from;
    while (i < plen) {
        while (i < plen && prefix[i] == '/') i++;
        size_t st = i;
        while (i < plen && prefix[i] != '/') i++;
        size_t l = i - st;
        if (l == 0) break;
        if (k >= v->n) return 0;
        if (v->len[k] != l ||
            zng_memcmp(v->s + v->off[k], prefix + st, l) != 0)
            return 0;
        k++;
    }
    return 1;
}

int zng_prefix_comps(const char *prefix)
{
    if (!prefix) return 0;
    if (zng_strlen(prefix) == 1 && prefix[0] == '/') return 0;
    int n = 0;
    size_t i = 0;
    while (prefix[i]) {
        while (prefix[i] == '/') i++;
        size_t st = i;
        while (prefix[i] && prefix[i] != '/') i++;
        if (i > st) n++;
    }
    return n;
}

int zng_pv_emit(char *out, size_t outn, size_t *olen,
                const struct zng_pv *v, int from, int to)
{
    if (!out || !olen || !v) return -ZNG_EINVAL;
    for (int k = from; k < to; k++) {
        if (*olen + 1 + v->len[k] + 1 > outn) return -ZNG_ENAMETOOLONG;
        out[(*olen)++] = '/';
        zng_memcpy(out + *olen, v->s + v->off[k], v->len[k]);
        *olen += v->len[k];
        out[*olen] = 0;
    }
    return 0;
}

static int emit_str(char *out, size_t outn, size_t *olen, const char *s)
{
    size_t l = zng_strlen(s);
    if (*olen + l + 1 > outn) return -ZNG_ENAMETOOLONG;
    zng_memcpy(out + *olen, s, l);
    *olen += l;
    out[*olen] = 0;
    return 0;
}

/* ================================================================== */
/* 翻译                                                                */
/* ================================================================== */

int zng_under_root(const struct zng_cfg *c, const char *host)
{
    if (!c || !host || c->root_len == 0) return 0;
    if (c->root_len == 1) return host[0] == '/';       /* root == "/" */
    if (zng_strncmp(host, c->root, c->root_len) != 0) return 0;
    return host[c->root_len] == 0 || host[c->root_len] == '/';
}

/*
 * 热路径判定：输入是否为"规范绝对路径"（无 `.`、`..`、`//`、尾斜杠）。
 *
 * 为什么值得单独判一次：绝大多数 open/stat 的路径都是规范形，慢路径却要为
 * 它们做一遍 pv_from（记录每个组件偏移）+ pv_clean（带栈的 .. 折叠）+ 每个
 * bind 各一次 pv_prefix（每次还会 strlen 前缀）+ 逐组件 emit（每个组件一次
 * 边界检查和一次 NUL 写入）。实测短路径 184ns/call，其中绝大部分是这些。
 *
 * 规范形下 cleaned == raw，`..` 折叠和组件重建都可以省掉，直接一次 memcpy。
 */
/*
 * 一次遍历同时得到：长度、是否为"规范绝对路径"（无 `.` / `..` / `//` / 尾斜杠）。
 * 合并成一趟是为了省掉热路径上的一次独立 strlen —— 两趟都逐字节走同一条串，
 * 在 100+ 字符的深路径上是实打实的两倍扫描。
 */
static size_t zng_scan_abs(const char *p, int *clean)
{
    *clean = 0;
    if (p[0] != '/') {                       /* 相对路径：只数长度 */
        size_t n = 0;
        while (p[n]) n++;
        return n;
    }
    size_t i = 0;
    int ok = 1;
    for (;;) {
        size_t run = 0;
        while (p[i] == '/') { i++; run++; }
        if (run > 1) ok = 0;                  /* "//" */
        if (!p[i]) {
            /* 尾斜杠（run > 0）才不规范。少了 run 这个条件，
             * 每个正常路径都会因为"长度 > 1"被判成不规范，
             * 快路径等于从未生效 —— A/B 基准一跑就露馅。 */
            if (run > 0 && i > 1) ok = 0;
            break;
        }
        size_t st = i;
        while (p[i] && p[i] != '/') i++;
        size_t cl = i - st;
        if (cl == 1 && p[st] == '.') ok = 0;
        else if (cl == 2 && p[st] == '.' && p[st + 1] == '.') ok = 0;
    }
    *clean = ok;
    return i;
}

/* 组件级前缀匹配：prefix 必须完整落在某个 '/' 边界上。
 * 不做 strlen —— 长度由调用方给（bind/root 的长度都在 cfg 里缓存好了）。 */
static int zng_comp_prefix(const char *path, size_t l,
                           const char *prefix, size_t plen)
{
    if (!prefix || plen == 0 || plen > l) return 0;
    if (zng_memcmp(path, prefix, plen) != 0) return 0;
    return plen == l || path[plen] == '/';
}
/*
 * guest -> host
 *
 * 语义（沿用 A 的正确设计，这里的实现去掉了所有静默降级）：
 *   · 相对路径：原样返回 0（解析层结合 dirfd / cwd 处理）
 *   · 幂等：已带 rootfs 前缀（组件级比对，非字符串前缀）-> 原样返回 0
 *   · bind：在 cleaned 视图上做最长前缀匹配，".." 按 mount 语义在 guest
 *           侧弹出并 clamp 在 "/"
 *   · rootfs 前缀：用 raw 视图，只 clamp **前导** ".."，中间的 ".." 保留，
 *           交给内核 / openat2 以真实符号链接语义解析
 *
 * 任何缓冲不足都返回 -ENAMETOOLONG —— [B] 的做法是"原样透传到 host"，
 * 那是把隔离漏洞伪装成一次成功的调用。
 */
int zng_translate(const struct zng_cfg *c, const char *in, char *out, size_t outn)
{
    if (!c || !in || !out || outn == 0) return -ZNG_EINVAL;

    int clean_abs = 0;
    size_t l = zng_scan_abs(in, &clean_abs);
    if (l == 0) { out[0] = 0; return 0; }

    if (in[0] != '/') {                       /* 相对路径 */
        if (l + 1 > outn) return -ZNG_ENAMETOOLONG;
        zng_memcpy(out, in, l + 1);
        return 0;
    }

    /*
     * 规范绝对路径的快路径：一次扫描判形 + 至多一次 memcpy。
     * 语义与下面的慢路径完全一致（规范形下 pv_clean 是恒等变换、
     * emit 等价于直接拼接），单元测试逐条覆盖两者。
     */
    if (clean_abs && in[0] == '/') {
        if (l == 1) {                             /* "/" */
            if (c->root_len == 0 || c->root_len + 1 > outn)
                return c->root_len == 0 ? 0 : -ZNG_ENAMETOOLONG;
            zng_memcpy(out, c->root, c->root_len);
            out[c->root_len] = 0;
            return 1;
        }

        /* (1) 已带 root 前缀：幂等，原样透传 */
        if (c->root_len > 1 && zng_comp_prefix(in, l, c->root, c->root_len)) {
            if (l + 1 > outn) return -ZNG_ENAMETOOLONG;
            zng_memcpy(out, in, l + 1);
            return 0;
        }

        /* (2) bind：最长 guest 前缀，剩余部分直接拼接 */
        int best = -1;
        size_t best_len = 0;
        for (int i = 0; i < c->nbinds; i++) {
            if (c->binds[i].guest_len > best_len &&
                zng_comp_prefix(in, l, c->binds[i].guest, c->binds[i].guest_len)) {
                best = i;
                best_len = c->binds[i].guest_len;
            }
        }
        if (best >= 0) {
            const struct zng_bind *b = &c->binds[best];
            size_t rest = l - b->guest_len;
            if (b->host_len + rest + 1 > outn) return -ZNG_ENAMETOOLONG;
            zng_memcpy(out, b->host, b->host_len);
            zng_memcpy(out + b->host_len, in + b->guest_len, rest);
            out[b->host_len + rest] = 0;
            return 1;
        }

        /* (3) 拼 root */
        if (c->root_len == 0) {                   /* 未配置 root：惰性 */
            if (l + 1 > outn) return -ZNG_ENAMETOOLONG;
            zng_memcpy(out, in, l + 1);
            return 0;
        }
        if (c->root_len + l + 1 > outn) return -ZNG_ENAMETOOLONG;
        zng_memcpy(out, c->root, c->root_len);
        zng_memcpy(out + c->root_len, in, l);
        out[c->root_len + l] = 0;
        return 1;
    }
    struct zng_pv raw, cln;
    int r = zng_pv_from(in, &raw);
    if (r < 0) return r;

    if (c->root_len > 1 && zng_pv_prefix(&raw, 0, c->root)) {
        if (l + 1 > outn) return -ZNG_ENAMETOOLONG;
        zng_memcpy(out, in, l + 1);
        return 0;
    }

    r = zng_pv_clean(&raw, &cln);
    if (r < 0) return r;

    int best = -1;
    size_t best_len = 0;
    for (int i = 0; i < c->nbinds; i++) {
        if (c->binds[i].guest_len > best_len &&
            zng_pv_prefix(&cln, 0, c->binds[i].guest)) {
            best = i;
            best_len = c->binds[i].guest_len;
        }
    }

    size_t olen = 0;
    if (best >= 0) {
        const struct zng_bind *b = &c->binds[best];
        int pc = zng_prefix_comps(b->guest);
        if (emit_str(out, outn, &olen, b->host)) return -ZNG_ENAMETOOLONG;
        if (zng_pv_emit(out, outn, &olen, &cln, pc, cln.n)) return -ZNG_ENAMETOOLONG;
        if (olen == 0) { out[0] = '/'; out[1] = 0; }
        return 1;
    }

    if (c->root_len == 0) {                   /* 未配置 root：惰性 */
        if (l + 1 > outn) return -ZNG_ENAMETOOLONG;
        zng_memcpy(out, in, l + 1);
        return 0;
    }

    int rs = 0;
    while (rs < raw.n && zng_pv_is_dotdot(&raw, rs)) rs++;
    if (emit_str(out, outn, &olen, c->root)) return -ZNG_ENAMETOOLONG;
    if (zng_pv_emit(out, outn, &olen, &raw, rs, raw.n)) return -ZNG_ENAMETOOLONG;
    if (olen == 0) { out[0] = '/'; out[1] = 0; }
    return 1;
}

/*
 * host -> guest（readlink / getcwd / /proc/self/exe 修复用）
 * 返回 0 = 不在沙箱内（out 为原路径），1 = 已转换。
 */
int zng_untranslate(const struct zng_cfg *c, const char *host, char *out, size_t outn)
{
    if (!c || !host || !out || outn == 0) return -ZNG_EINVAL;

    size_t l = zng_strlen(host);
    if (l == 0 || host[0] != '/') {
        if (l + 1 > outn) return -ZNG_ENAMETOOLONG;
        zng_memcpy(out, host, l + 1);
        return 0;
    }

    struct zng_pv v;
    int r = zng_pv_from(host, &v);
    if (r < 0) return r;

    int best = -1, best_is_root = 0;
    size_t best_len = 0;

    if (c->root_len > 0 &&
        zng_pv_prefix(&v, 0, c->root) && c->root_len >= best_len) {
        best_is_root = 1;
        best_len = c->root_len;
    }
    for (int i = 0; i < c->nbinds; i++) {
        if (c->binds[i].host_len > best_len &&
            zng_pv_prefix(&v, 0, c->binds[i].host)) {
            best = i;
            best_len = c->binds[i].host_len;
            best_is_root = 0;
        }
    }

    size_t olen = 0;
    if (best_is_root) {
        int rc = zng_prefix_comps(c->root);
        if (v.n > rc && zng_pv_emit(out, outn, &olen, &v, rc, v.n))
            return -ZNG_ENAMETOOLONG;
        if (olen == 0) { out[0] = '/'; out[1] = 0; }
        return 1;
    }
    if (best >= 0) {
        const struct zng_bind *b = &c->binds[best];
        int hc = zng_prefix_comps(b->host);
        if (emit_str(out, outn, &olen, b->guest)) return -ZNG_ENAMETOOLONG;
        if (zng_pv_emit(out, outn, &olen, &v, hc, v.n)) return -ZNG_ENAMETOOLONG;
        if (olen == 0) { out[0] = '/'; out[1] = 0; }
        return 1;
    }

    if (l + 1 > outn) return -ZNG_ENAMETOOLONG;
    zng_memcpy(out, host, l + 1);
    return 0;
}

/* ================================================================== */
/* ELF 解析（纯 buffer）                                               */
/* ================================================================== */

static uint64_t zng_ld_le(const unsigned char *p, int n)
{
    uint64_t v = 0;
    for (int i = 0; i < n; i++) v |= ((uint64_t)p[i]) << (8 * i);
    return v;
}

/*
 * 给至少 64 字节的 ELF header，返回"要解析 PT_INTERP 需要读入的总字节数"。
 * 返回 >0 = 字节数；<0 = -errno（-ENOEXEC 表示不是 ELF64/LSB 或布局异常）。
 *
 * [A] zt_elf_probe_fd 内部直接 lseek+pread，解析与 I/O 耦合 -> 无法单测。
 *     这里两步分离：先算 span，再喂 buffer，全部可测。
 */
long zng_elf_span(const unsigned char *h, size_t have)
{
    if (!h || have < 64) return -ZNG_EINVAL;
    if (h[0] != 0x7f || h[1] != 'E' || h[2] != 'L' || h[3] != 'F')
        return -ZNG_ENOEXEC;
    if (h[4] != 2) return -ZNG_ENOEXEC;              /* ELFCLASS64 */
    if (h[5] != 1) return -ZNG_ENOEXEC;              /* ELFDATA2LSB */

    uint64_t phoff = zng_ld_le(h + 0x20, 8);
    uint64_t phentsize = zng_ld_le(h + 0x36, 2);
    uint64_t phnum = zng_ld_le(h + 0x38, 2);

    if (phentsize != 56) return -ZNG_ENOEXEC;        /* ELF64 Phdr 固定 56 */
    if (phnum > 256) return -ZNG_ENOEXEC;

    uint64_t span = phoff + phentsize * phnum;
    if (span > (16UL << 20)) return -ZNG_ENOEXEC;    /* 16MB 上限，防畸形值 */
    if (span < 64) span = 64;
    return (long)span;
}

int zng_elf_interp(const unsigned char *b, size_t n, char *interp, size_t isz)
{
    if (!b || !interp || isz == 0) return -ZNG_EINVAL;
    if (n < 64) return -ZNG_EINVAL;

    long span = zng_elf_span(b, n);
    if (span < 0) return (int)span;
    if ((size_t)span > n) return -ZNG_EIO;           /* buffer 不足：调用方错 */

    uint64_t phoff = zng_ld_le(b + 0x20, 8);
    uint64_t phentsize = zng_ld_le(b + 0x36, 2);
    uint64_t phnum = zng_ld_le(b + 0x38, 2);

    for (uint64_t i = 0; i < phnum; i++) {
        const unsigned char *p = b + phoff + phentsize * i;
        if ((size_t)(p - b) + 56 > n) return -ZNG_EIO;
        uint32_t type = (uint32_t)zng_ld_le(p, 4);
        if (type != 3) continue;                     /* PT_INTERP */

        uint64_t off = zng_ld_le(p + 0x08, 8);
        uint64_t fsz = zng_ld_le(p + 0x20, 8);
        if (fsz == 0 || fsz > isz) return -ZNG_ENAMETOOLONG;
        if (off + fsz > n) return -ZNG_EIO;          /* interp 串越界 */

        zng_memcpy(interp, b + off, (size_t)fsz);
        interp[fsz - 1] = 0;                         /* PT_INTERP 自带 NUL */
        return ZNG_ELF_DYNAMIC;
    }

    if (phnum == 0) return ZNG_ELF_STATIC;
    return ZNG_ELF_STATIC;
}

/*
 * 只定位 PT_INTERP，不读内容。见 zng.h 中的说明：
 * 这是 exec 路径应当使用的接口（配合定点读取），
 * zng_elf_interp() 只在 buffer 已覆盖 interp 数据时才适用。
 */
int zng_elf_interp_loc(const unsigned char *b, size_t n,
                       uint64_t *out_off, uint64_t *out_sz)
{
    uint64_t phoff, phentsize, phnum;

    if (!b || !out_off || !out_sz) return -ZNG_EINVAL;
    if (n < 64) return -ZNG_EINVAL;

    long span = zng_elf_span(b, n);
    if (span < 0) return (int)span;
    if ((size_t)span > n) return -ZNG_EIO;      /* 连 phdr 表都没读全 */

    phoff = zng_ld_le(b + 0x20, 8);
    phentsize = zng_ld_le(b + 0x36, 2);
    phnum = zng_ld_le(b + 0x38, 2);

    for (uint64_t i = 0; i < phnum; i++) {
        const unsigned char *p = b + phoff + phentsize * i;
        if ((size_t)(p - b) + 56 > n) return -ZNG_EIO;
        uint32_t type = (uint32_t)zng_ld_le(p, 4);
        if (type != 3) continue;                /* PT_INTERP */

        *out_off = zng_ld_le(p + 0x08, 8);      /* p_offset */
        *out_sz = zng_ld_le(p + 0x20, 8);       /* p_filesz */
        if (*out_sz == 0) return -ZNG_ENOEXEC;
        return ZNG_ELF_DYNAMIC;
    }
    return ZNG_ELF_STATIC;
}

/* ================================================================== */
/* exec 计划                                                           */
/* ================================================================== */

static char *zng_mkstr(const char *k, const char *v)
{
    size_t kl = zng_strlen(k), vl = zng_strlen(v);
    char *s = (char *)zng_alloc(kl + vl + 2);
    if (!s) return (char *)0;
    zng_memcpy(s, k, kl);
    s[kl] = '=';
    zng_memcpy(s + kl + 1, v, vl + 1);
    return s;
}

/* 拼接 a + ":" + b（b 可空） */
static char *zng_join2(const char *a, const char *b)
{
    size_t al = zng_strlen(a), bl = b ? zng_strlen(b) : 0;
    char *s = (char *)zng_alloc(al + bl + 2);
    if (!s) return (char *)0;
    zng_memcpy(s, a, al);
    size_t o = al;
    if (bl) { s[o++] = ':'; zng_memcpy(s + o, b, bl); o += bl; }
    s[o] = 0;
    return s;
}

static const char *zng_envfind(char *const envp[], const char *key)
{
    if (!envp) return (const char *)0;
    for (char *const *e = envp; *e; e++)
        if (zng_envkey(*e, key)) return *e + zng_strlen(key) + 1;
    return (const char *)0;
}

/*
 * rootfs 的库搜索路径。
 *
 * 【真机实测（Alpaquita glibc）必须区分两种 libc】
 *
 *   glibc rootfs 的 /usr/lib 里放的是**编译期**用的 GNU ld script ——
 *   例如 libm.so 是个 ASCII 文本文件（开头是 "GNU ld script"），内容形如
 *       GROUP ( /usr/lib/libm.so.6  AS_NEEDED ( /usr/lib/libmvec.so.1 ) )
 *   把它放进库搜索路径后，ld.so 可能选中这个脚本并报
 *       CANNOT LINK EXECUTABLE "head": .../usr/lib/libm.so has bad ELF magic
 *   而 glibc 的**运行时**库（libm.so.6 等真实 ELF）都在 /lib，
 *   所以 glibc 场景只给 /lib 与 /lib64。
 *
 *   musl rootfs 没有这个区分（没有 ld script），沿用四目录列表。
 */
static char *zng_libpath(const struct zng_cfg *c)
{
    static const char *dirs_musl[] = { "/lib", "/usr/lib", "/lib64", "/usr/lib64", 0 };
    /*
     * Debian/Ubuntu 的运行时库不在 /lib，而在 multiarch 子目录
     * （/usr/lib/aarch64-linux-gnu）。不加这一条，bash/ls 这类
     * 依赖 libtinfo 的程序会报 "error while loading shared libraries"。
     * shim 只支持 arm64，所以这里可以直接写死 aarch64 的目录名。
     */
    static const char *dirs_glibc[] = { "/lib", "/usr/lib/aarch64-linux-gnu",
                                        "/lib64", 0 };
    const char **dirs = c->is_glibc ? dirs_glibc : dirs_musl;

    size_t total = 1;
    for (int i = 0; dirs[i]; i++) total += c->root_len + zng_strlen(dirs[i]) + 1;

    char *s = (char *)zng_alloc(total);
    if (!s) return (char *)0;
    size_t o = 0;
    for (int i = 0; dirs[i]; i++) {
        if (o) s[o++] = ':';
        zng_memcpy(s + o, c->root, c->root_len);
        o += c->root_len;
        size_t dl = zng_strlen(dirs[i]);
        zng_memcpy(s + o, dirs[i], dl);
        o += dl;
    }
    s[o] = 0;
    return s;
}

/*
 * 构造子进程环境（fixenv）。
 *
 * [B 0.1.8 的 bug] 对 envp==NULL（env -i / clearenv 之后）走特判分支，
 * 塞了一个**从未构造**的静态空串 -> 子进程收到 LD_PRELOAD="" -> ldso 静默
 * 忽略空值 -> 程序裸奔 -> 撞上 seccomp blocklist -> SIGSYS(159)。
 * => 这里 NULL 一律归一化为"空数组"，**无条件**走同一条构造路径。
 *
 * [A 的 bug] zt_env_overlay 返回的数组在 exec 失败路径上从未 free（只
 * free 了 nargv）-> 长生命周期进程反复 exec 失败时持续泄漏。
 * => 返回 zng_plan 的一部分，由 zng_plan_free 统一释放。
 */
char **zng_env_build(const struct zng_cfg *c, char *const envp[])
{
    if (!c) return (char **)0;

    /*
     * 归属不变式（ownership invariant）—— 这条规则让 zng_env_free 的释放
     * 判断变得可靠，是必须的：
     *
     *   凡 key 属于"注入集合"（LD_PRELOAD / ZNG_* / LD_LIBRARY_PATH / PATH）
     *   的条目，在输出数组里**一律是我们自己 malloc 的副本**；其余条目一律
     *   是直接借用 envp 的指针，永不释放。
     *
     * 因此这些 key 在复制阶段必须**无条件跳过原值**（包括 PATH —— 不能
     * "缺失时才新建"，否则借来的 PATH 会被误判成自有而 free 掉，即
     * use-after-free）。代价是每个 key 一次 strdup，可忽略。
     */
    int n = 0;
    for (char *const *e = envp; e && *e; e++) {
        if (zng_envkey(*e, "LD_PRELOAD")) continue;      /* 强制用我们的 */
        if (zng_envkey(*e, "ZNG_PRELOAD")) continue;
        if (zng_envkey(*e, "ZNG_ROOT")) continue;
        if (zng_envkey(*e, "ZNG_ARGV0")) continue;
        if (zng_envkey(*e, "ZNG_DEBUG")) continue;
        if (zng_envkey(*e, "ZNG_BINDS")) continue;
        if (zng_envkey(*e, "LD_LIBRARY_PATH")) continue; /* 重建 */
        if (zng_envkey(*e, "PATH")) continue;            /* 重建 */
        n++;
    }

    /*
     * 容量：n 个借用条目 + 注入集合 7 项（LD_LIBRARY_PATH / LD_PRELOAD /
     * ZNG_PRELOAD / ZNG_ROOT / PATH / ZNG_DEBUG / ZNG_BINDS）
     * + plan_build 可能追加的 ZNG_ARGV0 + 结尾 NULL。
     * 留到 n + 12，避免以后加一项就越界（A 的 n+16 是隐式契约，没有注释说明）。
     */
    char **nv = (char **)zng_alloc(sizeof(char *) * (unsigned long)(n + 12));
    if (!nv) return (char **)0;

    int m = 0;
    for (char *const *e = envp; e && *e; e++) {
        if (zng_envkey(*e, "LD_PRELOAD") ||
            zng_envkey(*e, "ZNG_PRELOAD") ||
            zng_envkey(*e, "ZNG_ROOT") ||
            zng_envkey(*e, "ZNG_ARGV0") ||
            zng_envkey(*e, "ZNG_DEBUG") ||
            zng_envkey(*e, "ZNG_BINDS") ||
            zng_envkey(*e, "LD_LIBRARY_PATH") ||
            zng_envkey(*e, "PATH")) continue;
        nv[m++] = *e;                                    /* 直接复用原指针 */
    }

    char *libs = zng_libpath(c);
    const char *old_libs = zng_envfind(envp, "LD_LIBRARY_PATH");
    if (libs) {
        char *final_libs = old_libs ? zng_join2(libs, old_libs) : libs;
        if (final_libs) {
            if (final_libs != libs) zng_free(libs);
            char *kv = zng_mkstr("LD_LIBRARY_PATH", final_libs);
            zng_free(final_libs);
            if (kv) nv[m++] = kv;
        } else {
            zng_free(libs);
        }
    }

    if (c->self[0]) {
        char *kv = zng_mkstr("LD_PRELOAD", c->self);
        if (kv) nv[m++] = kv;
        char *kv2 = zng_mkstr("ZNG_PRELOAD", c->self);
        if (kv2) nv[m++] = kv2;
    }
    if (c->root_len) {
        char *kv = zng_mkstr("ZNG_ROOT", c->root);
        if (kv) nv[m++] = kv;
    }
    {
        /* PATH 同样无条件重建（理由见上方"归属不变式"） */
        const char *old = zng_envfind(envp, "PATH");
        char *kv = zng_mkstr("PATH", old ? old :
                             "/usr/local/sbin:/usr/local/bin:/usr/sbin:"
                             "/usr/bin:/sbin:/bin");
        if (kv) nv[m++] = kv;
    }
    if (c->debug) {
        char *kv = zng_mkstr("ZNG_DEBUG", "1");
        if (kv) nv[m++] = kv;
    }

    /*
     * bind 表必须显式注入。
     * 【真机实测的 bug】原先只在复制阶段跳过 ZNG_BINDS，却从未注入它 ——
     * 于是父进程 binds=3，exec 出的子进程 binds=0，/proc /dev /sys 全部
     * 落到 rootfs 内部（不存在），guest 里的工具集体失灵。
     * 序列化格式与 zng_ctor.c 的 parse_binds 一致："host\tguest\n..."
     */
    if (c->nbinds > 0) {
        size_t need = 1;
        for (int i = 0; i < c->nbinds; i++)
            need += c->binds[i].host_len + 1 + c->binds[i].guest_len + 1;

        char *bs = (char *)zng_alloc(need + 8);
        if (bs) {
            size_t o = 0;
            int ok = 1;
            for (int i = 0; i < c->nbinds && ok; i++) {
                size_t want = c->binds[i].host_len + 1 +
                              c->binds[i].guest_len + 1;
                if (o + want + 1 > need + 8) { ok = 0; break; }
                zng_memcpy(bs + o, c->binds[i].host, c->binds[i].host_len);
                o += c->binds[i].host_len;
                bs[o++] = '\t';
                zng_memcpy(bs + o, c->binds[i].guest, c->binds[i].guest_len);
                o += c->binds[i].guest_len;
                bs[o++] = '\n';
            }
            bs[o] = 0;
            if (ok) {
                char *kv = zng_mkstr("ZNG_BINDS", bs);
                if (kv) nv[m++] = kv;
            }
            zng_free(bs);
        }
    }

    nv[m] = (char *)0;
    return nv;
}

void zng_env_free(char **env)
{
    if (!env) return;
    /* 注意：env 数组中既有"从 envp 借来的指针"（不释放），也有我们 malloc
     * 的（要释放）。两者无法从指针本身区分 —— 因此约定：
     * **env_build 只把自己构造的条目记在末尾**，借来的保持原顺序在前。
     * 这里按"是否以 ZNG_/LD_PRELOAD/LD_LIBRARY_PATH 开头"判断归属。
     */
    for (int i = 0; env[i]; i++) {
        const char *e = env[i];
        if (zng_envkey(e, "LD_PRELOAD") ||
            zng_envkey(e, "ZNG_PRELOAD") ||
            zng_envkey(e, "ZNG_ROOT") ||
            zng_envkey(e, "ZNG_ARGV0") ||
            zng_envkey(e, "ZNG_DEBUG") ||
            zng_envkey(e, "ZNG_BINDS") ||
            zng_envkey(e, "LD_LIBRARY_PATH") ||
            zng_envkey(e, "PATH"))
            zng_free(env[i]);
    }
    zng_free(env);
}

/*
 * 构造"经加载器启动目标程序"的 argv。
 *
 * musl : ld.so PROG argv[1..]            （musl 无 --argv0）
 * glibc: ld.so --argv0 A0 --library-path LIBS PROG argv[1..]
 *
 * [B] 只有 musl 一种形态（硬编码 ld-musl-aarch64.so.1），无法支持 glibc。
 * [A] 两种都有，但 musl 场景要靠栈上回溯修 argv[0]（zt_fixup_argv0），
 *     失败时静默放弃。
 * => 这里：glibc 用 --argv0 精确解决；musl 场景把期望的 argv0 经
 *    ZNG_ARGV0 传下去，由子进程的 ctor 采用"先 libc 全局变量、后栈回溯"
 *    的分级策略修复，且失败时日志可见（见 zng_ctor.c）。
 */
int zng_plan_build(const struct zng_cfg *c,
                   const char *prog_host, const char *interp_host,
                   char *const argv[], char *const envp[],
                   struct zng_plan *out)
{
    if (!c || !out || !prog_host || !interp_host) return -ZNG_EINVAL;
    out->argv = (char **)0;
    out->envp = (char **)0;

    /* 加载器种类判定：musl 用 "ldso PROG"，glibc 需要 --argv0/--library-path */
    int kind = ZNG_LD_OTHER;
    if (zng_strstr_local(interp_host, "musl")) kind = ZNG_LD_MUSL;
    else if (zng_strstr_local(interp_host, "ld-linux") ||
             zng_strstr_local(interp_host, "ld.so")) kind = ZNG_LD_GLIBC;
    out->ld_kind = kind;

    int argc = 0;
    if (argv) for (char *const *a = argv; *a; a++) argc++;

    int extra = (kind == ZNG_LD_GLIBC) ? 5 : 1;
    char **na = (char **)zng_alloc(sizeof(char *) * (unsigned long)(argc + extra + 2));
    if (!na) return -ZNG_ENOMEM;

    int m = 0;
    na[m] = zng_dup(interp_host);
    if (!na[m]) { zng_free(na); return -ZNG_ENOMEM; }
    m++;

    if (kind == ZNG_LD_GLIBC) {
        char *libs = zng_libpath(c);
        na[m++] = (char *)"--argv0";
        na[m] = zng_dup(argv && argv[0] ? argv[0] : prog_host);
        if (!na[m]) { zng_free(na); return -ZNG_ENOMEM; }
        m++;
        na[m++] = (char *)"--library-path";
        if (!libs) { zng_free(na); return -ZNG_ENOMEM; }
        na[m++] = libs;
    }

    na[m] = zng_dup(prog_host);
    if (!na[m]) { zng_free(na); return -ZNG_ENOMEM; }
    m++;

    for (int i = 1; i < argc; i++) na[m++] = argv[i];
    na[m] = (char *)0;
    out->argv = na;

    out->envp = zng_env_build(c, envp);
    if (!out->envp) { zng_plan_free(out); return -ZNG_ENOMEM; }

    /* musl 场景：把调用方期望的 argv0 传给子进程 ctor */
    if (kind == ZNG_LD_MUSL && argv && argv[0]) {
        int k = 0;
        for (char **q = out->envp; *q; q++) k++;
        char *kv = zng_mkstr("ZNG_ARGV0", argv[0]);
        if (kv) {
            out->envp[k] = kv;
            out->envp[k + 1] = (char *)0;
        }
    }
    return 0;
}

void zng_plan_free(struct zng_plan *p)
{
    if (!p) return;
    if (p->argv) {
        for (int i = 0; p->argv[i]; i++) {
            /* 只释放我们 dup 过的项：argv[0](interp)、prog_host、
             * glibc 的 --argv0 值与 --library-path 值；其余是借来的原指针。
             * 用"是否等于已知 dup 产物"判断不可行，故采用位置表：
             *   索引 0            = interp（自有）
             *   glibc: 2          = argv0 值（自有）
             *   glibc: 4          = library-path（自有）
             *   musl : 1 / glibc: 5 = prog（自有）
             */
            if (i == 0) { zng_free(p->argv[i]); continue; }
            if (p->ld_kind == ZNG_LD_GLIBC && (i == 2 || i == 4 || i == 5)) {
                zng_free(p->argv[i]);
                continue;
            }
            if (p->ld_kind != ZNG_LD_GLIBC && i == 1) zng_free(p->argv[i]);
        }
        zng_free(p->argv);
        p->argv = (char **)0;
    }
    if (p->envp) { zng_env_free(p->envp); p->envp = (char **)0; }
}
