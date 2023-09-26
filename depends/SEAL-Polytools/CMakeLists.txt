cmake_minimum_required(VERSION 3.14)

project(polytools LANGUAGES CXX)

#######################
#  Dependency: JSON   #
#######################
include(FetchContent)

FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.10.5/json.tar.xz)
FetchContent_MakeAvailable(json)

#######################
#  Polytools Library  #
#######################
# For ringSNARK, SEAL is built along with SEAL-Polytools, but not installed # find_package(SEAL 4.0 REQUIRED)

add_library(polytools)
target_sources(polytools PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/src/poly_arith.cpp
  )

target_include_directories(polytools PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)

target_link_libraries(polytools PUBLIC nlohmann_json::nlohmann_json)

if(TARGET SEAL::seal)
    target_link_libraries(polytools PUBLIC SEAL::seal)
elseif(TARGET SEAL::seal_shared)
    target_link_libraries(polytools PUBLIC SEAL::seal_shared)
else()
    message(FATAL_ERROR "Cannot find target SEAL::seal or SEAL::seal_shared")
endif()

########################
#   Polytools Tests    #
########################
if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    add_subdirectory(test)
endif()


########################
#  Polytools Example   #
########################
add_executable(polytools-example)
target_sources(polytools-example PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/example.cpp
  )
target_link_libraries(polytools-example PRIVATE polytools)
