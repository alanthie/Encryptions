cmake_minimum_required(VERSION 3.22)
project(crypto)

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
include_directories(../../wide-decimal ../../wide-integer /usr/include)

add_executable(crypto
				../src/main.cpp
				../src/AESa.cpp
				../src/Base64.cpp
				../src/DES.cpp
				../src/SHA256.cpp
				../src/SymAlg.cpp
				../src/common/includes.cpp
				../src/crc32a.cpp
				../src/exclusive-lock-file.cpp
				../src/qa/Bin2PNG/lodepng.cpp
				../src/qa/RSA-GMP/RSAGMP.cpp
				../src/qa/RSA-GMP/RSAGMPPrime.cpp
				../src/qa/RSA-GMP/RSAGMPTest.cpp
				../src/qa/RSA-GMP/RSAGMPUtils.cpp
				../src/qa/RSA-GMP/RSAGMPmainTest.cpp
				../src/qa/RSA_generate/bigint/BigInteger.cc
				../src/qa/RSA_generate/bigint/BigIntegerAlgorithms.cc
				../src/qa/RSA_generate/bigint/BigIntegerUtils.cc
				../src/qa/RSA_generate/bigint/BigUnsigned.cc
				../src/qa/RSA_generate/bigint/BigUnsignedInABase.cc
				../src/qa/SystemProperties.cpp
				../src/qa/ecc_point/ecc_curve.cpp
				../src/qa/ecc_point/ecc_elgamal.cpp
				../src/qa/rsa_gen.cpp
				../src/twofish.c
				../src/twofish_cfb.c
				../src/vigenere.cpp
)

link_libraries(gmp curl pthread gmpxx)

if(EXISTS /usr/lib/x86_64-linux-gnu/libgmp.a)
  set(GMPLIB libgmp.a)
else()
  set(GMPLIB gmp)
endif()
if(EXISTS /usr/lib64/libgmp.a)
  set(GMPLIB libgmp.a)
endif()

target_link_libraries(	crypto
	${GMPLIB}
	curl
	pthread
)


