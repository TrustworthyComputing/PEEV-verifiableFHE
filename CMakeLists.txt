cmake_minimum_required(VERSION 3.20)

project(ringsnark LANGUAGES CXX)

# Local header files here ONLY

# Executables

add_executable(vppc Driver.cpp)
target_sources(vppc PRIVATE ${CMAKE_CURRENT_LIST_DIR}/Driver.cpp)
target_link_libraries(vppc PRIVATE ringsnark)

add_executable(vppc2 Driver_larger_params.cpp)
target_sources(vppc2 PRIVATE ${CMAKE_CURRENT_LIST_DIR}/Driver_larger_params.cpp)
target_link_libraries(vppc2 PRIVATE ringsnark)

add_executable(vppc3 Driver_eq_check.cpp)
target_sources(vppc3 PRIVATE ${CMAKE_CURRENT_LIST_DIR}/Driver_eq_check.cpp)
target_link_libraries(vppc3 PRIVATE ringsnark)

#add_executable(bench)
#target_sources(bench PRIVATE ${CMAKE_CURRENT_LIST_DIR}/microbench.cpp)
#target_link_libraries(bench PRIVATE ringsnark)


# Includes
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/depends")
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/ringsnark")

target_include_directories(ringsnark INTERFACE ${CMAKE_CURRENT_LIST_DIR}/include/)
include_directories(.)



# Libraries
## lib: SEAL
# find_package(SEAL 4.0 REQUIRED)
if (TARGET SEAL::seal)
    target_link_libraries(ringsnark INTERFACE SEAL::seal)
elseif (TARGET SEAL::seal_shared)
    target_link_libraries(ringsnark INTERFACE SEAL::seal_shared)
else ()
    message(FATAL_ERROR "Cannot find target SEAL::seal or SEAL::seal_shared")
endif ()


find_package(Boost 1.82.0 COMPONENTS math)

## lib: polytools
target_link_libraries(ringsnark INTERFACE polytools)
target_include_directories(ringsnark INTERFACE ${Boost_INCLUDE_DIRS})
target_link_libraries(ringsnark INTERFACE ${Boost_LIBRARIES})

