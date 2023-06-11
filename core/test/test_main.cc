#include <nos_core.h>

int test_logger();

int main()
{
    int ret;

    ret = test_logger();
    if (ret != 0) {
        return -1;
    }

    return 0;
}
