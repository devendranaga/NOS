#ifndef __CORE_SRC_AOS_THREAD_H__
#define __CORE_SRC_AOS_THREAD_H__

#define AOS_THREAD_PRIO_DEFAULT 10
#define AOS_THREAD_DEFAULT_CORE 0
#define AOS_THREAD_DEFAULT_DETACHED true

struct  aos_thread_data {
    int priority;
    int cpu_core;
    void *usrdata;
    bool detachable;
    void * (*start_func)(void *data);
};

typedef struct aos_thread_data aos_thread_data_t;

#define AOS_THREAD_DATA_INIT(__ptr) {\
    __ptr->priority = AOS_THREAD_PRIO_DEFAULT;\
    __ptr->cpu_core = AOS_THREAD_DEFAULT_CORE;\
    __ptr->usrdata = NULL;\
    __ptr->detachable = AOS_THREAD_DEFAULT_DETACHED;\
    __ptr->start_func = NULL;\
}

void *aos_thread_create(aos_thread_data_t *thr_data);
void aos_thread_destroy(void *ptr);

#endif

