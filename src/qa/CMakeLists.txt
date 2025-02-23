cmake_minimum_required(VERSION 3.18)
project(qa)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")

#include(FindCURL)
#find_package(CURL REQUIRED)
#if (NOT CURL_FOUND)
#    message (FATAL_ERROR "Curl is not supported")
#endif (NOT CURL_FOUND)
#include_directories(CURL_INCLUDE_DIRS)
#set(CMAKE_REQUIRED_LIBRARIES "${CURL_LIBRARIES}")
#list(APPEND LIBS "${CURL_LIBRARIES}")

# Many distros path
LINK_DIRECTORIES(/usr/lib64 /usr/lib/x86_64-linux-gnu)
include_directories(../../../wide-decimal ../../../wide-integer /usr/include)

add_executable(qa
		../Base64.cpp
		../SHA256.cpp
		../crc32a.cpp
		../qa/Bin2PNG/lodepng.cpp
		../qa/RSA-GMP/RSAGMP.cpp
		../qa/RSA-GMP/RSAGMPPrime.cpp
		../qa/RSA-GMP/RSAGMPTest.cpp
		../qa/RSA-GMP/RSAGMPUtils.cpp
		../qa/RSA-GMP/RSAGMPmainTest.cpp
		../qa/RSA_generate/bigint/BigInteger.cc
		../qa/RSA_generate/bigint/BigIntegerAlgorithms.cc
		../qa/RSA_generate/bigint/BigIntegerUtils.cc
		../qa/RSA_generate/bigint/BigUnsigned.cc
		../qa/RSA_generate/bigint/BigUnsignedInABase.cc
		../qa/SimpleECC/src/ecc.cpp
		../qa/SimpleECC/src/helper.cpp
		../qa/SimpleECC/src/j_point.cpp
		../qa/SimpleECC/src/point.cpp
		../qa/SimpleECC/src/simple_ecc_test.cpp
		../qa/SystemProperties.cpp
		../qa/ecc_point/ecc_curve.cpp
		../qa/ecc_point/ecc_elgamal.cpp
		../qa/menu/cfg_menu.cpp
		../qa/menu/eccdomain_menu.cpp
		../qa/menu/ecckey_menu.cpp
		../qa/menu/hh_menu.cpp
		../qa/menu/menu.cpp
		../qa/menu/menu_io.cpp
		../qa/menu/puzzle_menu.cpp
		../qa/menu/rsa_menu.cpp
		../qa/menu/tools_menu.cpp
		../qa/menu/wbaes_menu.cpp
		../qa/qa.cpp
		../vigenere.cpp
)

link_libraries(gmp ntl pthread gmpxx)

if(EXISTS /usr/lib/x86_64-linux-gnu/libgmp.a)
  set(GMPLIB libgmp.a)
else()
  set(GMPLIB gmp)
endif()
if(EXISTS /usr/lib64/libgmp.a)
  set(GMPLIB libgmp.a)
endif()

target_link_libraries( qa
	/usr/local/lib/libntl.a 
	${GMPLIB}						 
	pthread
)


