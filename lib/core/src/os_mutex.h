#include <pthread.h>

struct os_mutex {
    pthread_mutex_t mutex;
};

typedef struct os_mutex os_mutex_t;
