/* SPDX-License-Identifier: MIT */
/* zexec —— exec 热路径基准：fork + exec(N 次)，测每次 exec 的端到端开销
 * 用法：zexec [次数] [路径]     默认 200 次 /bin/true
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
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
    long n = argc > 1 ? atol(argv[1]) : 200;
    const char *prog = argc > 2 ? argv[2] : "/bin/true";
    double best = 1e30;

    for (int rep = 0; rep < 3; rep++) {
        double t0 = now_ns();
        for (long i = 0; i < n; i++) {
            pid_t p = fork();
            if (p == 0) {
                execl(prog, prog, (char *)0);
                _exit(127);
            }
            if (p < 0) { perror("fork"); return 1; }
            int st = 0;
            if (waitpid(p, &st, 0) < 0) { perror("waitpid"); return 1; }
            if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
                printf("子进程失败: exit=%d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
                return 1;
            }
        }
        double dt = (now_ns() - t0) / (double)n;
        if (dt < best) best = dt;
    }
    printf("zexec: %s × %ld → %.0f µs/exec\n", prog, n, best / 1000.0);
    return 0;
}
