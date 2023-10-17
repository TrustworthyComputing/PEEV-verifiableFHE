cmake_minimum_required(VERSION 3.20)

project(ringsnark LANGUAGES CXX)

# Executables


#add_executable(ringsnark-example10 example10.cpp)
#target_sources(ringsnark-example10 PRIVATE ${CMAKE_CURRENT_LIST_DIR}/example10.cpp)
#target_link_libraries(ringsnark-example10 PRIVATE ringsnark)

#add_executable(ringsnark-example6 example6.cpp)
#target_sources(ringsnark-example6 PRIVATE ${CMAKE_CURRENT_LIST_DIR}/example6.cpp)
#target_link_libraries(ringsnark-example6 PRIVATE ringsnark)

#add_executable(ringsnark-example11 example11.cpp)
#target_sources(ringsnark-example11 PRIVATE ${CMAKE_CURRENT_LIST_DIR}/example11.cpp)
#target_link_libraries(ringsnark-example11 PRIVATE ringsnark)

add_executable(ringsnark-example12 example12.cpp)
target_sources(ringsnark-example12 PRIVATE ${CMAKE_CURRENT_LIST_DIR}/example12.cpp)
target_link_libraries(ringsnark-example12 PRIVATE ringsnark)

add_executable(bench)
target_sources(bench PRIVATE ${CMAKE_CURRENT_LIST_DIR}/microbench.cpp)
target_link_libraries(bench PRIVATE ringsnark)


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

