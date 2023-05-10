cmake_minimum_required(VERSION 3.8)

project(auto_os_c)

include(./build_args.cmake)

add_subdirectory(./lib/core/)
add_subdirectory(./services/firewall/)
add_subdirectory(./services/logger/)
add_subdirectory(./lib/crypto/)

