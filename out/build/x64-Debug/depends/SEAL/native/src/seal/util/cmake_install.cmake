# Install script for directory: F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "F:/UD/Thesis/ringSNARK/out/install/x64-Debug")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Debug")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/SEAL-4.1/seal/util" TYPE FILE FILES
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/blake2.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/blake2-impl.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/clang.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/clipnormal.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/common.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/croots.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/defines.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/dwthandler.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/fips202.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/galois.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/gcc.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/globals.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/hash.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/hestdparms.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/iterator.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/locks.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/mempool.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/msvc.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/numth.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/pointer.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/polyarithsmallmod.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/polycore.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/rlwe.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/rns.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/scalingvariant.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/ntt.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/streambuf.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/uintarith.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/uintarithmod.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/uintarithsmallmod.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/uintcore.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/util/ztools.h"
    )
endif()

