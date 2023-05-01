#include <os_mutex.h>

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
