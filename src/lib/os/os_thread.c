#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <sched.h>
#include <firewall_common.h>
#include <os_thread.h>

/* Thread context structure. */
struct os_thread_context {
    pthread_t tid;
    int priority;
    int cpu_core;
    bool detachable;
};

/* Set default attribute as detached. */
STATIC void os_thread_attr_default_detached(pthread_attr_t *attr)
{
    pthread_attr_init(attr);
    pthread_attr_setdetachstate(attr, PTHREAD_CREATE_DETACHED);
}

STATIC int os_thread_set_cpu(pthread_t *thr, int cpu_core)
{
    cpu_set_t cpuset;
    int ret;

    CPU_ZERO(&cpuset);
    CPU_SET(cpu_core, &cpuset);
    ret = pthread_setaffinity_np(*thr, sizeof(cpu_set_t), &cpuset);
    if (ret < 0) {
        return -1;
    }

    return 0;
}

void *os_thread_create(int priority, int cpu_core, void *usrdata,
                       bool detachable, void * (*start_func)(void *data))
{
    struct os_thread_context *ctx;
    pthread_attr_t attr;
    int ret;

    ctx = calloc(1, sizeof(struct os_thread_context));
    if (!ctx) {
        return NULL;
    }

    ctx->priority = priority;
    ctx->cpu_core = cpu_core;
    ctx->detachable = detachable;

    if (detachable) {
        os_thread_attr_default_detached(&attr);
    }

    ret = pthread_create(&ctx->tid, &attr, start_func, usrdata);
    if (ret < 0) {
        goto free_ctx;
    }

    os_thread_set_cpu(&ctx->tid, cpu_core);

    return ctx;

free_ctx:
    if (ctx) {
        free(ctx);
    }

    return NULL;
}

void os_mutex_create(struct os_mutex *mutex)
{
    pthread_mutex_init(&mutex->mutex, NULL);
}

void os_mutex_lock(struct os_mutex *mutex)
{
    pthread_mutex_lock(&mutex->mutex);
}

void os_mutex_unlock(struct os_mutex *mutex)
{
    pthread_mutex_unlock(&mutex->mutex);
}

void os_cond_create(struct os_cond *cond)
{
    pthread_cond_init(&cond->cond, NULL);
}

void os_cond_wait(struct os_cond *cond, struct os_mutex *mutex)
{
    pthread_cond_wait(&cond->cond, &mutex->mutex);
}

void os_cond_signal(struct os_cond *cond)
{
    pthread_cond_signal(&cond->cond);
}

