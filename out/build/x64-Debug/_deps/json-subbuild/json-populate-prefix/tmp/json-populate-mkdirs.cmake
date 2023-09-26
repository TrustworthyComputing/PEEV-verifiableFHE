# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/_deps/json-src"
  "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/_deps/json-build"
  "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/_deps/json-subbuild/json-populate-prefix"
  "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/_deps/json-subbuild/json-populate-prefix/tmp"
  "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/_deps/json-subbuild/json-populate-prefix/src/json-populate-stamp"
  "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/_deps/json-subbuild/json-populate-prefix/src"
  "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/_deps/json-subbuild/json-populate-prefix/src/json-populate-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/_deps/json-subbuild/json-populate-prefix/src/json-populate-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/_deps/json-subbuild/json-populate-prefix/src/json-populate-stamp${cfgdir}") # cfgdir has leading slash
endif()
