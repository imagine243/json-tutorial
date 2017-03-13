cmake_minimum_required(VERSION 2.6)
project(leptjson_test C)

if(CMAKE_C_COMPILE_ID MATCHES "GNU|Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ansi -pedantic -Wall")
endif()

target_link_libraries(leptjson_test leptjson)