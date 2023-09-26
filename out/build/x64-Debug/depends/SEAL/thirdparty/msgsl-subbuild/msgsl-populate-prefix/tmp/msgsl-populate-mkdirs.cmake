# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/depends/SEAL/thirdparty/msgsl-src"
  "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/depends/SEAL/thirdparty/msgsl-build"
  "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/depends/SEAL/thirdparty/msgsl-subbuild/msgsl-populate-prefix"
  "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/depends/SEAL/thirdparty/msgsl-subbuild/msgsl-populate-prefix/tmp"
  "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/depends/SEAL/thirdparty/msgsl-subbuild/msgsl-populate-prefix/src/msgsl-populate-stamp"
  "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/depends/SEAL/thirdparty/msgsl-subbuild/msgsl-populate-prefix/src"
  "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/depends/SEAL/thirdparty/msgsl-subbuild/msgsl-populate-prefix/src/msgsl-populate-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/depends/SEAL/thirdparty/msgsl-subbuild/msgsl-populate-prefix/src/msgsl-populate-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/depends/SEAL/thirdparty/msgsl-subbuild/msgsl-populate-prefix/src/msgsl-populate-stamp${cfgdir}") # cfgdir has leading slash
endif()
