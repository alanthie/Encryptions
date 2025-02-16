cmake_minimum_required( VERSION 3.16 )

project( tst LANGUAGES CXX )

find_package(Catch2 3 REQUIRED)

#-- compile catch2 v3 from git - make install:
#-- Installing: /usr/local/lib/libCatch2.a
#-- Installing: /usr/local/lib/libCatch2Main.a
LINK_DIRECTORIES(/usr/local/lib )

add_executable( 0010-TestFibo 0010-TestFibo.cpp)
target_link_libraries( 0010-TestFibo PRIVATE Catch2::Catch2WithMain)

