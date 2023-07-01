#include <string.h>
#include <nos_utils.h>

namespace nos::core
{

int convert_to_int(const std::string &val_str, int *val_int)
{
    char *err = nullptr;

    *val_int = strtol(val_str.c_str(), &err, 10);
    if (err && (*err != '\0')) {
        return -1;
    }

    return 0;
}

int convert_to_uint(const std::string &val_str, uint32_t *val_uint)
{
    char *err = nullptr;

    *val_uint = strtoul(val_str.c_str(), &err, 10);
    if (err && (*err != '\0')) {
        return -1;
    }

    return 0;
}

}
