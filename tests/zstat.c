/* SPDX-License-Identifier: MIT */
/* zstat —— 设备端 stat/open 热路径基准（走 shim 的真实路径解析）
 * 用法：zstat [迭代次数]
 * 输出：每类操作的 ns/op（取 3 轮最小值）
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static double now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

int main(int argc, char **argv)
{
    long n = argc > 1 ? atol(argv[1]) : 20000;
    struct stat st;
    int fd;

    printf("zstat: iters=%ld\n", n);
    for (int rep = 0; rep < 3; rep++) {
        double t0 = now_ns();
        for (long i = 0; i < n; i++) {
            if (stat("/usr/bin/bash", &st) != 0) { perror("stat"); return 1; }
        }
        double t1 = now_ns();
        for (long i = 0; i < n; i++) {
            fd = open("/usr/bin/bash", O_RDONLY);
            if (fd < 0) { perror("open"); return 1; }
            close(fd);
        }
        double t2 = now_ns();
        for (long i = 0; i < n; i++) {
            if (access("/etc/os-release", R_OK) != 0) { perror("access"); return 1; }
        }
        double t3 = now_ns();
        printf("rep%d  stat %6.0f ns/op | open+close %6.0f ns/op | access %6.0f ns/op\n",
               rep, (t1 - t0) / n, (t2 - t1) / n, (t3 - t2) / n);
        fflush(stdout);
    }
    return 0;
}
