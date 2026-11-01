/* SPDX-License-Identifier: MIT */
/* zsigsys —— 判断 Android 的 app seccomp 用 TRAP 还是 KILL，并抓出 syscall 号
 *
 * 用法（在 App 进程里跑）：zsigsys <syscall_nr>
 *   若过滤器是 SECCOMP_RET_TRAP，handler 能拿到 si_syscall 并打印；
 *   若是 KILL_PROCESS，进程直接死，什么都不打印。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

static void on_sigsys(int sig, siginfo_t *si, void *ctx)
{
    (void)sig; (void)ctx;
    char buf[128];
    int n = snprintf(buf, sizeof buf, "SIGSYS caught: si_syscall=%d si_code=%d\n",
                     (int)si->si_syscall, (int)si->si_code);
    if (n > 0) { ssize_t w = write(2, buf, (size_t)n); (void)w; }
    _exit(157);
}

int main(int argc, char **argv)
{
    long nr = argc > 1 ? atol(argv[1]) : 449;   /* 默认 futex_waitv */
    struct sigaction sa;
    sa.sa_sigaction = on_sigsys;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSYS, &sa, NULL) != 0) { perror("sigaction"); return 2; }

    printf("probing nr=%ld (handler installed)\n", nr);
    fflush(stdout);
    long r = syscall(nr, 0, 0, 0, 0, 0, 0);
    printf("returned %ld errno=%d (未被拦)\n", r, errno);
    return 0;
}
