cmake_minimum_required(VERSION 3.22)

project(crypto_dummy)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
option(BUILD_TEST "Build unit test" ON)

add_subdirectory(src)
add_subdirectory(src/qa)
if(${BUILD_TEST})
	add_subdirectory(unittest)
endif()




