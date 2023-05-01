#include "os_mutex.h"
#include "os_cond.h"

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
