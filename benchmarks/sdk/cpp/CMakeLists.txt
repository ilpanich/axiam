# AXIAM C++ SDK benchmark — CMake glue.
#
# Standalone project (not folded into the parent axiam/ Cargo workspace, which
# doesn't apply here anyway — this is the only CMake project in the repo).
# Builds the sibling axiam-cplusplus-sdk checkout via add_subdirectory(), the
# least-egress path: no vcpkg/Conan registry fetch, no installed package
# required, just the checkout that already lives next to this repo. Swap for
# find_package(axiam-cpp-sdk CONFIG REQUIRED) (vcpkg/Conan) once the alpha
# package is published — see TODO.md.
cmake_minimum_required(VERSION 3.16)
project(axiam_cpp_sdk_bench CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# Path to the sibling SDK checkout. Overridable (-DAXIAM_CPP_SDK_DIR=...) for
# maintainers who keep the checkout elsewhere.
set(AXIAM_CPP_SDK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../../axiam-cplusplus-sdk"
    CACHE PATH "Path to the sibling axiam-cplusplus-sdk checkout")
get_filename_component(AXIAM_CPP_SDK_DIR "${AXIAM_CPP_SDK_DIR}" ABSOLUTE)

if(NOT EXISTS "${AXIAM_CPP_SDK_DIR}/CMakeLists.txt")
  message(FATAL_ERROR
    "sibling axiam-cplusplus-sdk checkout not found at ${AXIAM_CPP_SDK_DIR} "
    "— clone ilpanich/axiam-cplusplus-sdk next to this repo, or pass "
    "-DAXIAM_CPP_SDK_DIR=<path>.")
endif()

# Don't build the SDK's own tests/examples as part of the bench build.
set(AXIAM_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(AXIAM_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
add_subdirectory("${AXIAM_CPP_SDK_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/axiam-cpp-sdk")

find_package(Threads REQUIRED)

add_executable(axiam-bench bench.cpp)
target_link_libraries(axiam-bench PRIVATE axiam::axiam_cpp Threads::Threads)
