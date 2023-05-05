/**
 * @brief - Implements OS Thread routines.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
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

/* Set CPU for this specific thread id. */
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

/* Destroy the thread. */
void os_thread_destroy(void *ptr)
{
    struct os_thread_context *ctx = ptr;

    if (ctx) {
        pthread_kill(ctx->tid, SIGQUIT);
        free(ctx);
    }
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

    /* Create detachable thread if asked. */
    if (detachable) {
        os_thread_attr_default_detached(&attr);
    }

    /* Create thread and assign the startup function. */
    ret = pthread_create(&ctx->tid, &attr, start_func, usrdata);
    if (ret < 0) {
        goto free_ctx;
    }

    /* Set CPU for this thread. */
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

