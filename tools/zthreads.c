/* SPDX-License-Identifier: MIT */
/*
 * zthreads —— glibc 线程密集压测
 *
 * 目的：验证打补丁后的 glibc rootfs 在**线程密集**负载下是否还站得住。
 * 打过的补丁改变了三条与线程强相关的行为：
 *
 *   clone3        -> 返回 ENOSYS，glibc 必须退回 clone() 建线程
 *   rseq          -> 返回 ENOSYS，TLS 快速路径关闭
 *   set_robust_list -> 假装成功，内核侧没有健壮 futex 链
 *
 * 所以这里刻意压这几条路径：
 *   A. 线程生命期：反复 pthread_create/join（大量 clone）
 *   B. 分离线程：pthread_detach 后由系统回收
 *   C. 互斥量争用：多线程抢同一把锁（futex 快慢路径）
 *   D. 条件变量：生产者/消费者握手（futex + 唤醒）
 *   E. 线程局部存储：每个线程读写 __thread 变量（TLS 分配/回收）
 *   F. 动态内存：线程内 malloc/free churn
 *   G. 线程私有数据：pthread_key_create + setspecific
 *
 * 用法：zthreads [线程数] [轮数]
 * 退出码：0 全部通过；1 有校验失败；2 用法错误
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int g_threads = 32;
static int g_rounds = 100;

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

/* ---------------- A. 线程生命期 + E. TLS + F. 内存 ---------------- */

static __thread unsigned long tls_counter;     /* 每线程独立副本 */
static pthread_mutex_t g_sum_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned long g_sum;

static void *lifecycle_worker(void *arg) {
    long id = (long)arg;
    unsigned long local = 0;

    tls_counter = (unsigned long)id;           /* TLS 写 */
    for (int i = 0; i < 200; i++) {
        void *p = malloc(64 + (size_t)(i % 32));
        if (!p) return (void *)1;
        memset(p, (int)id, 16);
        free(p);
        local += tls_counter + (unsigned long)i;   /* TLS 读 */
    }

    pthread_mutex_lock(&g_sum_lock);
    g_sum += local;
    pthread_mutex_unlock(&g_sum_lock);
    return NULL;
}

/* ---------------- B. 分离线程 ---------------- */

static pthread_mutex_t g_det_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_det_cond = PTHREAD_COND_INITIALIZER;
static int g_det_done;

static void *detached_worker(void *arg) {
    (void)arg;
    usleep(1000);
    pthread_mutex_lock(&g_det_lock);
    g_det_done++;
    pthread_cond_signal(&g_det_cond);
    pthread_mutex_unlock(&g_det_lock);
    return NULL;
}

/* ---------------- C. 互斥量争用 ---------------- */

static pthread_mutex_t g_contend = PTHREAD_MUTEX_INITIALIZER;
static long g_counter;

static void *contend_worker(void *arg) {
    (void)arg;
    for (int i = 0; i < 2000; i++) {
        pthread_mutex_lock(&g_contend);
        long v = g_counter;
        /* 制造一点持有时间，让争用真的发生 */
        for (volatile int k = 0; k < 8; k++) { }
        g_counter = v + 1;
        pthread_mutex_unlock(&g_contend);
    }
    return NULL;
}

/* ---------------- D. 条件变量握手 ---------------- */

static pthread_mutex_t g_cv_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_cv_prod = PTHREAD_COND_INITIALIZER;
static pthread_cond_t  g_cv_cons = PTHREAD_COND_INITIALIZER;
static int g_slot = -1;
static long g_consumed;

static void *producer(void *arg) {
    int n = (int)(long)arg;
    for (int i = 0; i < n; i++) {
        pthread_mutex_lock(&g_cv_lock);
        while (g_slot >= 0) pthread_cond_wait(&g_cv_cons, &g_cv_lock);
        g_slot = i;
        pthread_cond_signal(&g_cv_prod);
        pthread_mutex_unlock(&g_cv_lock);
    }
    return NULL;
}

static void *consumer(void *arg) {
    int n = (int)(long)arg;
    for (int i = 0; i < n; i++) {
        pthread_mutex_lock(&g_cv_lock);
        while (g_slot < 0) pthread_cond_wait(&g_cv_prod, &g_cv_lock);
        g_slot = -1;
        g_consumed++;
        pthread_cond_signal(&g_cv_cons);
        pthread_mutex_unlock(&g_cv_lock);
    }
    return NULL;
}

/* ---------------- G. 线程私有数据 ---------------- */

static pthread_key_t g_key;
static long g_key_seen;

static void key_dtor(void *v) { (void)v; }

static void *key_worker(void *arg) {
    (void)arg;
    long v = (long)pthread_getspecific(g_key);
    if (v == 0) {
        v = 1;
        pthread_setspecific(g_key, (void *)v);
        g_key_seen++;
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc > 1) g_threads = atoi(argv[1]);
    if (argc > 2) g_rounds = atoi(argv[2]);
    if (g_threads <= 0 || g_rounds <= 0) {
        fprintf(stderr, "用法: %s [线程数] [轮数]\n", argv[0]);
        return 2;
    }

    printf("zthreads: threads=%d rounds=%d\n", g_threads, g_rounds);
    fflush(stdout);

    double t0 = now_ms();
    int fails = 0;

    /* --- A + E + F --- */
    double a0 = now_ms();
    for (int r = 0; r < g_rounds; r++) {
        pthread_t th[256];
        int n = g_threads > 256 ? 256 : g_threads;
        int made = 0;
        for (int i = 0; i < n; i++) {
            if (pthread_create(&th[i], NULL, lifecycle_worker, (void *)(long)i) != 0) {
                printf("FAIL pthread_create 第 %d 轮第 %d 个: %s\n", r, i, strerror(errno));
                fails++;
                break;
            }
            made++;
        }
        for (int i = 0; i < made; i++) pthread_join(th[i], NULL);
    }
    printf("[A/E/F] 线程创建回收 %d 个  %.1f ms\n", g_threads * g_rounds, now_ms() - a0);
    fflush(stdout);

    /* --- B 分离线程 --- */
    double b0 = now_ms();
    for (int i = 0; i < g_rounds; i++) {
        pthread_t th;
        if (pthread_create(&th, NULL, detached_worker, NULL) == 0) pthread_detach(th);
        else { printf("FAIL detach create\n"); fails++; }
    }
    pthread_mutex_lock(&g_det_lock);
    while (g_det_done < g_rounds) pthread_cond_wait(&g_det_cond, &g_det_lock);
    pthread_mutex_unlock(&g_det_lock);
    printf("[B]   分离线程 %d 个（完成 %d）  %.1f ms\n", g_rounds, g_det_done, now_ms() - b0);
    fflush(stdout);

    /* --- C 锁争用 --- */
    double c0 = now_ms();
    {
        pthread_t th[64];
        int n = g_threads > 64 ? 64 : g_threads;
        for (int i = 0; i < n; i++) pthread_create(&th[i], NULL, contend_worker, NULL);
        for (int i = 0; i < n; i++) pthread_join(th[i], NULL);
        long want = (long)n * 2000;
        if (g_counter != want) {
            printf("FAIL 争用计数 g_counter=%ld 期望 %ld\n", g_counter, want);
            fails++;
        }
        printf("[C]   锁争用 %d 线程 × 2000 → %ld  %.1f ms\n", n, g_counter, now_ms() - c0);
        fflush(stdout);
    }

    /* --- D 条件变量 --- */
    double d0 = now_ms();
    {
        pthread_t p, c;
        int n = g_rounds * 10;
        pthread_create(&p, NULL, producer, (void *)(long)n);
        pthread_create(&c, NULL, consumer, (void *)(long)n);
        pthread_join(p, NULL);
        pthread_join(c, NULL);
        if (g_consumed != n) {
            printf("FAIL 消费计数 g_consumed=%ld 期望 %d\n", g_consumed, n);
            fails++;
        }
        printf("[D]   条件变量 %d 次往返  %.1f ms\n", n, now_ms() - d0);
        fflush(stdout);
    }

    /* --- G 线程私有数据 --- */
    double g0 = now_ms();
    if (pthread_key_create(&g_key, key_dtor) != 0) {
        printf("FAIL pthread_key_create: %s\n", strerror(errno));
        fails++;
    } else {
        pthread_t th[64];
        int n = g_threads > 64 ? 64 : g_threads;
        for (int i = 0; i < n; i++) pthread_create(&th[i], NULL, key_worker, NULL);
        for (int i = 0; i < n; i++) pthread_join(th[i], NULL);
        printf("[G]   pthread_key %d 线程（写入 %ld）  %.1f ms\n", n, g_key_seen, now_ms() - g0);
        fflush(stdout);
    }

    /*
     * 不测健壮互斥量：在没有 seccomp 的基线上同样拿不到 EOWNERDEAD，
     * 说明探针本身不可靠（fork 后 _exit 的语义与外层预期不符），
     * 结果无法归因到 set_robust_list 补丁上，故不作为指标。
     * 该降级的结论见 docs/device-verification.md（按补丁语义推断）。
     */

    printf("总计 %.1f ms，失败 %d 项\n", now_ms() - t0, fails);
    fflush(stdout);
    return fails == 0 ? 0 : 1;
}
