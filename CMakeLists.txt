cmake_minimum_required(VERSION 3.21)
project(tunnlix_key_rp2350 LANGUAGES C)

# Standalone entry point for the firmware's selected portable core dependency.
option(KEY_CORE_BUILD_TESTS "Build portable core checks" ${PROJECT_IS_TOP_LEVEL})
if(KEY_CORE_BUILD_TESTS)
    enable_testing()
endif()
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/key-core.cmake")
