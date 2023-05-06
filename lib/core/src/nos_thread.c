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
#include <nos_thread.h>

/* Thread context structure. */
struct aos_thread_context {
    pthread_t tid;
    int priority;
    int cpu_core;
    bool detachable;
};

/* Set default attribute as detached. */
static void os_thread_attr_default_detached(pthread_attr_t *attr)
{
    pthread_attr_init(attr);
    pthread_attr_setdetachstate(attr, PTHREAD_CREATE_DETACHED);
}

/* Set CPU for this specific thread id. */
static int os_thread_set_cpu(pthread_t *thr, int cpu_core)
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
void aos_thread_destroy(void *ptr)
{
    struct aos_thread_context *ctx = ptr;

    if (ctx) {
        pthread_kill(ctx->tid, SIGQUIT);
        free(ctx);
    }
}

void *aos_thread_create(aos_thread_data_t *thr_data)
{
    struct aos_thread_context *ctx;
    pthread_attr_t attr;
    int ret;

    ctx = calloc(1, sizeof(struct aos_thread_context));
    if (!ctx) {
        return NULL;
    }

    ctx->priority = thr_data->priority;
    ctx->cpu_core = thr_data->cpu_core;
    ctx->detachable = thr_data->detachable;

    /* Create detachable thread if asked. */
    if (thr_data->detachable) {
        os_thread_attr_default_detached(&attr);
    }

    /* Create thread and assign the startup function. */
    ret = pthread_create(&ctx->tid, &attr, thr_data->start_func, thr_data->usrdata);
    if (ret < 0) {
        goto free_ctx;
    }

    /* Set CPU for this thread. */
    os_thread_set_cpu(&ctx->tid, thr_data->cpu_core);

    return ctx;

free_ctx:
    if (ctx) {
        free(ctx);
    }

    return NULL;
}

