cmake_minimum_required(VERSION 2.6)
project(leptjson_test1 C)

if(CMAKE_C_COMPILE_ID MATCHES "GNU|Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ansi -pedantic -Wall")
endif()

add_library(leptjson leptjson.c)
add_executable(leptjson_test1 test.c)
target_link_libraries(leptjson_test1 leptjson)