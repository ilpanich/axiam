# AXIAM C SDK bench — builds bench.c against the sibling axiam-c-sdk checkout.
#
# The tagged release may not be resolvable via vcpkg/Conan in this environment
# (registry fetches are egress-blocked), so — same as the go/rust benches use a
# module replace / path dependency — this pulls the sibling axiam-c-sdk
# checkout straight into the build with add_subdirectory(), the lowest-egress
# option CMake supports (no package manager, no network fetch). Swap this for
# find_package(axiam-c-sdk CONFIG REQUIRED) against a published/installed
# package once the alpha is on a registry (see TODO.md).
cmake_minimum_required(VERSION 3.16)
project(axiam_c_sdk_bench LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# benchmarks/sdk/c/ -> .. -> sdk -> .. -> benchmarks -> .. -> axiam -> .. -> the
# monorepo checkout root, next to which the sibling SDK repos are cloned (same
# depth the go/rust benches use for ../../../../axiam-<lang>-sdk).
set(AXIAM_C_SDK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../../axiam-c-sdk" CACHE PATH
    "Path to the sibling axiam-c-sdk checkout")

if(NOT EXISTS "${AXIAM_C_SDK_DIR}/CMakeLists.txt")
    message(FATAL_ERROR
        "axiam-c-sdk checkout not found at ${AXIAM_C_SDK_DIR} — clone "
        "ilpanich/axiam-c-sdk there, or pass -DAXIAM_C_SDK_DIR=<path>.")
endif()

# Build only the SDK library, statically, so the bench binary is self-contained
# (no LD_LIBRARY_PATH juggling to run ./build/axiam-bench directly from run.sh).
set(AXIAM_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(AXIAM_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(AXIAM_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(AXIAM_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(AXIAM_ENABLE_COVERAGE OFF CACHE BOOL "" FORCE)

add_subdirectory(${AXIAM_C_SDK_DIR} ${CMAKE_CURRENT_BINARY_DIR}/axiam-c-sdk)

add_executable(axiam-bench bench.c)
target_link_libraries(axiam-bench PRIVATE axiam::axiam)
