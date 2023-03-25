cmake_minimum_required(VERSION 3.8)

project(Firewall)

if(CONFIG_USE_CLANG)
	set(CMAKE_C_COMPILER "/usr/bin/clang")
elseif(CONFIG_USE_GCC)
	set(CMAKE_C_COMPILER "/usr/bin/gcc")
endif()

set(DRV_SRC
	./src/drivers/driver_generic.c
	./src/drivers/linux_raw/linux_raw.c)

set(OS_SRC
	./src/lib/os/os_thread.c)

set(PROTOCOL_SRC
	./src/lib/protocols/protocol_generic.c
	./src/lib/protocols/l2/ethernet.c
	./src/lib/protocols/l2/arp.c
	./src/lib/protocols/l3/ipv4.c)

set(LIB_SRC
	./src/lib/fw_pkt.c
	${PROTOCOL_SRC})

set(MAIN_SRC
	./src/main/firewall.c)

set(SRC
	${DRV_SRC}
	${MAIN_SRC}
	${OS_SRC}
	${LIB_SRC})

set(FW_FLAGS "-DCONFIG_DRIVER_RAW_SOCKET")

set(CMAKE_C_FLAGS "-Wall -Wno-unused-parameter -Wextra -Werror ${FW_FLAGS}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wshadow -Wno-deprecated-declarations")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat-security")

include_directories(./src/
					./src/drivers/
					./src/drivers/linux_raw/
					./src/main
					./src/lib/
					./src/lib/os/
					./src/lib/protocols/
					./src/lib/protocols/l2/
					./src/lib/protocols/l3/
					./src/events/)

add_executable(fwd ${SRC})
target_link_libraries(fwd pthread)

