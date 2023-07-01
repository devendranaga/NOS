#ifndef __NOS_UTILS_H__
#define __NOS_UTILS_H__

#include <cstdint>
#include <string>

namespace nos::core
{

int convert_to_int(const std::string &val_str, int *val_int);
int convert_to_uint(const std::string &val_str, uint32_t *val_uint);

}

#endif
