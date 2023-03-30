#ifndef __OS_THREAD_H__
#define __OS_THREAD_H__

#include <stdbool.h>
#include <pthread.h>

struct os_mutex {
    pthread_mutex_t mutex;
};

typedef struct os_mutex os_mutex_t;

struct os_cond {
    pthread_cond_t cond;
};

typedef struct os_cond os_cond_t;

void *os_thread_create(int priority, int cpu_core, void *usrdata,
                       bool detachable, void * (*start_func)(void *data));
void os_mutex_create(struct os_mutex *mutex);
void os_mutex_lock(struct os_mutex *mutex);
void os_mutex_unlock(struct os_mutex *mutex);

void os_cond_create(struct os_cond *cond);
void os_cond_wait(struct os_cond *cond, struct os_mutex *mutex);
void os_cond_signal(struct os_cond *cond);

#endif

