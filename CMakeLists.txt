cmake_minimum_required(VERSION 3.22)

project(crypto_dummy)
set(CMAKE_CXX_STANDARD 20)

#include_directories(~/dev/libevent/include )
#link_directories(~/dev/libevent/build/lib)

add_subdirectory(src)
add_subdirectory(src/qa)


