# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

if(EXISTS "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/depends/SEAL/thirdparty/zlib-subbuild/zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-gitclone-lastrun.txt" AND EXISTS "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/depends/SEAL/thirdparty/zlib-subbuild/zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-gitinfo.txt" AND
  "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/depends/SEAL/thirdparty/zlib-subbuild/zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-gitclone-lastrun.txt" IS_NEWER_THAN "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/depends/SEAL/thirdparty/zlib-subbuild/zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-gitinfo.txt")
  message(STATUS
    "Avoiding repeated git clone, stamp file is up to date: "
    "'F:/UD/Thesis/ringSNARK/out/build/x64-Debug/depends/SEAL/thirdparty/zlib-subbuild/zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-gitclone-lastrun.txt'"
  )
  return()
endif()

execute_process(
  COMMAND ${CMAKE_COMMAND} -E rm -rf "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/depends/SEAL/thirdparty/zlib-src"
  RESULT_VARIABLE error_code
)
if(error_code)
  message(FATAL_ERROR "Failed to remove directory: 'F:/UD/Thesis/ringSNARK/out/build/x64-Debug/depends/SEAL/thirdparty/zlib-src'")
endif()

# try the clone 3 times in case there is an odd git clone issue
set(error_code 1)
set(number_of_tries 0)
while(error_code AND number_of_tries LESS 3)
  execute_process(
    COMMAND "C:/Program Files/Git/cmd/git.exe" 
            clone --no-checkout --config "advice.detachedHead=false" "https://github.com/madler/zlib.git" "zlib-src"
    WORKING_DIRECTORY "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/depends/SEAL/thirdparty"
    RESULT_VARIABLE error_code
  )
  math(EXPR number_of_tries "${number_of_tries} + 1")
endwhile()
if(number_of_tries GREATER 1)
  message(STATUS "Had to git clone more than once: ${number_of_tries} times.")
endif()
if(error_code)
  message(FATAL_ERROR "Failed to clone repository: 'https://github.com/madler/zlib.git'")
endif()

execute_process(
  COMMAND "C:/Program Files/Git/cmd/git.exe" 
          checkout "04f42ceca40f73e2978b50e93806c2a18c1281fc" --
  WORKING_DIRECTORY "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/depends/SEAL/thirdparty/zlib-src"
  RESULT_VARIABLE error_code
)
if(error_code)
  message(FATAL_ERROR "Failed to checkout tag: '04f42ceca40f73e2978b50e93806c2a18c1281fc'")
endif()

set(init_submodules TRUE)
if(init_submodules)
  execute_process(
    COMMAND "C:/Program Files/Git/cmd/git.exe" 
            submodule update --recursive --init 
    WORKING_DIRECTORY "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/depends/SEAL/thirdparty/zlib-src"
    RESULT_VARIABLE error_code
  )
endif()
if(error_code)
  message(FATAL_ERROR "Failed to update submodules in: 'F:/UD/Thesis/ringSNARK/out/build/x64-Debug/depends/SEAL/thirdparty/zlib-src'")
endif()

# Complete success, update the script-last-run stamp file:
#
execute_process(
  COMMAND ${CMAKE_COMMAND} -E copy "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/depends/SEAL/thirdparty/zlib-subbuild/zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-gitinfo.txt" "F:/UD/Thesis/ringSNARK/out/build/x64-Debug/depends/SEAL/thirdparty/zlib-subbuild/zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-gitclone-lastrun.txt"
  RESULT_VARIABLE error_code
)
if(error_code)
  message(FATAL_ERROR "Failed to copy script-last-run stamp file: 'F:/UD/Thesis/ringSNARK/out/build/x64-Debug/depends/SEAL/thirdparty/zlib-subbuild/zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-gitclone-lastrun.txt'")
endif()
