# Install script for directory: F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal

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
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/SEAL-4.1/seal" TYPE FILE FILES
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/batchencoder.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/ciphertext.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/ckks.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/modulus.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/context.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/decryptor.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/dynarray.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/encryptionparams.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/encryptor.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/evaluator.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/galoiskeys.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/keygenerator.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/kswitchkeys.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/memorymanager.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/plaintext.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/publickey.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/randomgen.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/randomtostd.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/relinkeys.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/seal.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/secretkey.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/serializable.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/serialization.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/valcheck.h"
    "F:/UD/Thesis/ringSNARK/depends/SEAL/native/src/seal/version.h"
    )
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("F:/UD/Thesis/ringSNARK/out/build/x64-Debug/depends/SEAL/native/src/seal/util/cmake_install.cmake")

endif()

