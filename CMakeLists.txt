cmake_minimum_required(VERSION 3.8)

project(Firewall)

set(DRV_SRC
	./src/drivers/driver_generic.c
	./src/drivers/linux_raw/linux_raw.c)

set(OS_SRC
	./src/lib/os/os_thread.c)

set(LIB_SRC
	./src/lib/fw_pkt.c)

set(MAIN_SRC
	./src/main/firewall.c)

set(SRC
	${DRV_SRC}
	${MAIN_SRC}
	${OS_SRC}
	${LIB_SRC})

set(FW_FLAGS "-DCONFIG_DRIVER_RAW_SOCKET")

set(CMAKE_C_FLAGS "-Wall -Wno-unused-parameter -Wextra -Werror ${FW_FLAGS}")

include_directories(./src/
					./src/drivers/
					./src/drivers/linux_raw/
					./src/main
					./src/lib/
					./src/lib/os/)

add_executable(fwd ${SRC})
target_link_libraries(fwd pthread)

