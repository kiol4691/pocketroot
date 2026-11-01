/* SPDX-License-Identifier: MIT */
/*
 * zprobe —— 在 App 进程的 seccomp 环境里逐条探测 syscall 是否被放行。
 *
 * 为什么需要它：
 *   adb shell 的进程 Seccomp=0（没有过滤器），所以 glibc rootfs 在 shell 里
 *   跑得通，一进 App 进程就 exit=159(SIGSYS)。要定位到底是哪条 syscall
 *   被拦，只能在**继承了 zygote 过滤器的进程**里逐条试。
 *
 * 用法（由 App 以 assets/zprobe 拷到私有目录后 exec）：
 *   zprobe            # 打印每条 syscall 的结果
 * 输出每行：<名字> <结果>，结果为 SIGSYS 表示被过滤器杀死。
 *
 * 子进程退出码/信号的区分：被 seccomp 拦是 SIGSYS 而不是返回 EPERM，
 * 所以必须 fork 才能观察到 —— 同进程里被 SIGSYS 打死就什么都打印不出来了。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

struct probe {
    const char *name;
    long nr;
    const char *why;
};

/* 关注点：glibc 2.3x+ 启动/NPTL 初始化会用到的、且 musl 不用的 syscall。 */
static const struct probe PROBES[] = {
    /* --- 对照组：必然放行 --- */
    { "getpid",          172, "对照" },
    { "gettid",          178, "对照" },
    { "mprotect",        226, "loader 必需" },
    /* --- 已知被拦（patch-glibc-syscalls.py 打的就是这些）--- */
    { "rseq",            293, "glibc TLS 快速路径" },
    { "set_robust_list", 99,  "NPTL 初始化" },
    { "membarrier",      283, "NPTL 初始化" },
    { "clone3",          435, "线程创建" },
    { "futex_waitv",     449, "多 futex 等待" },
    { "faccessat2",      439, "access" },
    { "statx",           291, "stat" },
    { "openat2",         437, "shim 主引擎" },
    /* --- 启动路径其它候选 --- */
    { "set_tid_address", 96,  "csu 初始化" },
    { "prctl",           167, "csu/loader" },
    { "prlimit64",       261, "csu" },
    { "brk",             214, "malloc" },
    { "mmap",            222, "loader" },
    { "munmap",          215, "loader" },
    { "madvise",         233, "loader" },
    { "futex",           98,  "pthread" },
    { "rt_sigaction",    134, "signal" },
    { "rt_sigprocmask",  135, "signal" },
    { "rt_sigreturn",    139, "signal" },
    { "getdents64",      61,  "目录" },
    { "clock_gettime",   113, "时间" },
    { "uname",           160, "loader" },
    { "getrandom",       278, "栈保护" },
    { "clone",           220, "线程创建" },
    { "execve",          221, "exec" },
    { "execveat",        281, "exec" },
    { "close_range",     436, "fd 管理" },
    { "pidfd_open",      434, "glibc 2.36+" },
    { "sched_getaffinity", 123, "nproc" },
    { "sched_setaffinity", 122, "pthread" },
    { "getcpu",          168, "NUMA" },
    { "sysinfo",         179, "内存信息" },
    { "readlinkat",      78,  "loader" },
    { "newfstatat",      79,  "stat" },
    { "openat",          56,  "文件" },
    { "openat2",         437, "重复确认" },
};

#define N (sizeof(PROBES) / sizeof(PROBES[0]))

int main(int argc, char **argv)
{
    /* --range：把 1..460 全扫一遍，只打印被拦的（用来找"到底是哪条"）。 */
    if (argc > 1 && strcmp(argv[1], "--range") == 0) {
        /* exit/exit_group 会直接结束子进程，属正常，不列为拦 */
        for (long nr = 1; nr <= 460; nr++) {
            pid_t p = fork();
            if (p == 0) {
                alarm(1);              /* pause/sigsuspend 会一直阻塞，靠闹钟收尸 */
                syscall(nr, 0, 0, 0, 0, 0, 0);
                _exit(0);
            }
            int st = 0;
            waitpid(p, &st, 0);
            if (WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS)
                printf("BLOCKED %ld\n", nr);
        }
        printf("range done\n");
        return 0;
    }

    printf("zprobe: pid=%d ppid=%d\n", (int)getpid(), (int)getppid());
    fflush(stdout);

    for (size_t i = 0; i < N; i++) {
        pid_t p = fork();
        if (p == 0) {
            /* 子进程：只发一条 syscall，参数给 0/NULL ——
             * 关键是"是否到达内核"，返回 EINVAL/EFAULT 都算放行。 */
            errno = 0;
            long r = syscall(PROBES[i].nr, 0, 0, 0, 0, 0, 0);
            if (r < 0) printf("%-18s ret=-1 errno=%d(%s)\n", PROBES[i].name,
                               errno, strerror(errno));
            else printf("%-18s ret=%ld\n", PROBES[i].name, r);
            fflush(stdout);
            _exit(0);
        }
        int st = 0;
        waitpid(p, &st, 0);
        if (WIFSIGNALED(st)) {
            int sig = WTERMSIG(st);
            printf("%-18s SIGSYS(BLOCKED)  # %s\n", PROBES[i].name, PROBES[i].why);
            if (sig != SIGSYS) printf("   (意外信号 %d:%s)\n", sig, strsignal(sig));
        }
        fflush(stdout);
    }
    printf("zprobe: done\n");
    return 0;
}
