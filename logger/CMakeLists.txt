cmake_minimum_required(VERSION 3.10)

project(logger)

set(SRC
	./src/logger.cc)

include_directories(./src/
					./include/
					../core/include/)

add_executable(nos_logger ${SRC})
target_link_libraries(nos_logger nos_core pthread)

