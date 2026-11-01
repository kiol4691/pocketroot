/* SPDX-License-Identifier: MIT */
/*
 * bench_translate —— zng_translate 热路径微基准
 *
 * 为什么单独做一个：路径翻译是 shim 每个 open/stat/exec 都要过的纯 CPU 逻辑，
 * 与 syscall、Android、rootfs 全都无关 —— 可以在开发机上直接量、直接比。
 * 真机上量它反而更难：Engine A（openat2）会额外带来 openat2/readlink/close
 * 三个 syscall，把翻译本身的开销盖掉。
 *
 * 用法：make -C tests bench && tests/bench_translate [迭代次数]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ZNG_HOST_TEST 1
#include "zng.h"

static double now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

struct cand {
    const char *name;
    const char *path;
};

int main(int argc, char **argv)
{
    long iters = argc > 1 ? atol(argv[1]) : 300000;

    struct zng_cfg c;
    if (zng_cfg_init(&c) != 0) { printf("cfg_init 失败\n"); return 1; }
    const char *root = "/data/user/0/com.pocketroot/files/rootfs";
    snprintf(c.root, sizeof c.root, "%s", root);
    c.root_len = strlen(c.root);
    zng_cfg_bind_add(&c, "/dev", "/dev");
    zng_cfg_bind_add(&c, "/proc", "/proc");
    zng_cfg_bind_add(&c, "/sys", "/sys");

    static const struct cand cands[] = {
        { "短路径    /usr/bin/busybox",        "/usr/bin/busybox" },
        { "深路径    /usr/lib/..umath.so",     "/usr/lib/python3.12/site-packages/numpy/core/_multiarray_umath.cpython-312-aarch64-linux-gnu.so" },
        { "bind      /proc/self/status",       "/proc/self/status" },
        { "相对      rel/path/file.txt",       "rel/path/file.txt" },
        { "根        /",                       "/" },
        { "含 ..    /tmp/a/../../b/./c",       "/tmp/a/../../b/./c" },
    };

    char out[ZNG_PATH_MAX];
    printf("%-34s %10s %10s   %s\n", "用例", "ns/call", "改写?", "输出前缀");
    printf("%-34s %10s %10s   %s\n", "----------------------------------",
           "----------", "----------", "--------");

    /* 每例取 5 轮的最小值：这台机器上单轮波动能到 2 倍，
     * 用最小值反映代码本身的开销，而不是调度噪声。 */
    for (size_t k = 0; k < sizeof cands / sizeof cands[0]; k++) {
        long acc = 0;
        int rw = -1;
        double best = 1e30;
        for (int rep = 0; rep < 5; rep++) {
            double t0 = now_ns();
            for (long i = 0; i < iters; i++) {
                int r = zng_translate(&c, cands[k].path, out, sizeof out);
                if (r < 0) { printf("translate 失败: %d\n", r); return 1; }
                rw = r;
                acc += (long)out[0] + (long)out[1];   /* 防止被优化掉 */
            }
            double dt = (now_ns() - t0) / (double)iters;
            if (dt < best) best = dt;
        }
        printf("%-34s %10.1f %10s   %s\n", cands[k].name, best,
               rw ? "yes" : "no", out[0] ? out : "(empty)");
        (void)acc;
    }

    zng_cfg_free(&c);
    return 0;
}
