#include <pthread.h>

struct os_cond {
    pthread_cond_t cond;
};

typedef struct os_cond os_cond_t;
