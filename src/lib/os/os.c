#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <os.h>

int os_wait_for_timeout(uint32_t timeout_ms)
{
    struct timeval timeout;

    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = ((timeout_ms % 1000) * 1000);

    return select(0, NULL, NULL, NULL, &timeout);
}

