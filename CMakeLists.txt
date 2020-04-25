cmake_minimum_required(VERSION 3.5)

if (NOT CMAKE_BUILD_TYPE)
    message(STATUS "No build type selected, defaulting to Release")
    set(CMAKE_BUILD_TYPE "Release")
endif ()

set(SOURCES
      x16r.c
      algo/blake.c
      algo/bmw.c
      algo/groestl.c
      algo/jh.c
      algo/keccak.c
      algo/skein.c
      algo/cubehash.c
      algo/echo.c
      algo/luffa.c
      algo/simd.c
      algo/hamsi.c
      algo/hamsi_helper.c
      algo/fugue.c
      algo/shavite.c
      algo/shabal.c
      algo/whirlpool.c
      algo/sha2big.c
      aes/aes.c
)

add_library(x16r_hash STATIC ${SOURCES})

