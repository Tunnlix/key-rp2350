cmake_minimum_required(VERSION 3.21)
function(rp2350_check_capacity setting minimum maximum)
    if(DEFINED ${setting} AND NOT "${${setting}}" STREQUAL "")
        if(NOT "${${setting}}" MATCHES "^[1-9][0-9]*$" OR
            ${setting} LESS minimum OR ${setting} GREATER maximum)
            message(FATAL_ERROR "${setting} must be between ${minimum} and ${maximum} for the RP2350 storage provider")
        endif()
    endif()
endfunction()
rp2350_check_capacity(CTAP_RESIDENT_CAPACITY 1 32)
rp2350_check_capacity(CTAP_MESSAGE_CAPACITY 1024 2048)
# Invoke this entry point separately; the portable root never imports the SDK.
if(NOT PICO_SDK_PATH AND DEFINED ENV{PICO_SDK_PATH})
    set(PICO_SDK_PATH "$ENV{PICO_SDK_PATH}")
endif()
if(NOT EXISTS "${PICO_SDK_PATH}/external/pico_sdk_import.cmake")
    message(FATAL_ERROR "Set PICO_SDK_PATH to the pinned Pico SDK 2.3.1 checkout")
endif()
set(PICO_BOARD seeed_xiao_rp2350 CACHE STRING "Target board")
set(PICO_PLATFORM rp2350-arm-s CACHE STRING "Initial single-core Arm target")
set(PICO_RP2350_A2_SUPPORTED OFF CACHE BOOL "Legacy A2 errata support (unsupported by this flash layout)")
if(PICO_RP2350_A2_SUPPORTED)
    message(FATAL_ERROR "This A4 flash layout cannot include the A2/E10 absolute UF2 block; set PICO_RP2350_A2_SUPPORTED=OFF")
endif()
if(NOT PICO_BOARD STREQUAL "seeed_xiao_rp2350" OR NOT PICO_PLATFORM STREQUAL "rp2350-arm-s")
    message(FATAL_ERROR "This integration currently supports XIAO RP2350 Arm only")
endif()
include("${PICO_SDK_PATH}/external/pico_sdk_import.cmake")
project(ctap_rp2350 LANGUAGES C CXX ASM)
set(CMAKE_C_STANDARD 17)
# SDK runtime uses GNU Arm asm; ctap_core and our source files remain strict C17.
set(CMAKE_C_EXTENSIONS ON)
pico_sdk_init()
if(NOT PICO_SDK_VERSION_STRING STREQUAL "2.3.1")
    message(FATAL_ERROR "Reviewed integration requires Pico SDK 2.3.1")
endif()
option(RP2350_CORE_LTO "Enable LTO for the core/providers; keep SDK objects outside LTO" OFF)
if(CMAKE_INTERPROCEDURAL_OPTIMIZATION)
    message(FATAL_ERROR "Use RP2350_CORE_LTO instead of global IPO: SDK 2.3.1/GCC 15 full LTO is not supported here")
endif()
add_subdirectory(../.. portable-core)
include(cmake/crypto.cmake)
include(cmake/storage.cmake)

add_library(rp2350_board_flash STATIC board_flash.c flash_geometry.c)
target_include_directories(rp2350_board_flash PUBLIC "${CMAKE_CURRENT_FUNCTION_LIST_DIR}")
target_link_libraries(rp2350_board_flash PUBLIC ctap_core pico_stdlib hardware_flash rp2350_flash_guard)
target_compile_options(rp2350_board_flash PRIVATE -fstack-usage)
pico_enable_stdio_usb(rp2350_board_flash 0)
pico_enable_stdio_uart(rp2350_board_flash 0)

# Application flash/RAM layout; provisioning has a separate RAM-only image.
function(rp2350_configure_image image)
    target_include_directories(${image} PRIVATE "${CMAKE_CURRENT_FUNCTION_LIST_DIR}")
    target_link_libraries(${image} PRIVATE ctap_core pico_stdlib)
    # SDK INTERFACE sources include intentional Arm extensions; enforce strict
    # C only on our sources, not on third-party implementation files.
    target_compile_options(${image} PRIVATE -fstack-usage)
    # No SDK stdio transports; the normal application owns its FIDO HID interface.
    pico_enable_stdio_usb(${image} 0)
    pico_enable_stdio_uart(${image} 0)
    pico_set_binary_type(${image} default)
    target_compile_definitions(${image} PRIVATE PICO_STACK_SIZE=16384 PICO_CORE1_STACK_SIZE=0)
    pico_add_linker_script_override_path(${image} "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/linker"
        FILES memory_flash.incl memory_ram.incl sections_stack.incl section_extra_post_end.incl)
    target_link_options(${image} PRIVATE -Wl,--print-memory-usage)
    pico_add_extra_outputs(${image})
endfunction()

add_library(rp2350_status_led INTERFACE)
target_sources(rp2350_status_led INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/status_led.c")
target_include_directories(rp2350_status_led INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(rp2350_status_led INTERFACE pico_status_led)
target_compile_definitions(rp2350_status_led INTERFACE
    PICO_COLORED_STATUS_LED_USE_DEFAULT_ALARM_POOL=0
    PICO_COLORED_STATUS_LED_RESET_DELAY_US=300)

add_executable(rp2350_application application_main.c ab_boot.c usb_transport.c
    usb_descriptors.c presence.c entropy.c board_entropy.c stack_probe.c)
target_link_libraries(rp2350_application PRIVATE rp2350_storage_codec
    rp2350_board_flash hardware_watchdog tinyusb_device pico_unique_id pico_bootrom rp2350_status_led)
target_include_directories(rp2350_application SYSTEM PRIVATE "${PICO_TINYUSB_PATH}/src")
pico_set_program_name(rp2350_application "Key")
target_compile_definitions(rp2350_application PRIVATE PICO_CRT0_IMAGE_TYPE_TBYB=1)
# ROM selection version, not OTP anti-rollback. The byte-sized minor/build
# components share the 16-bit ROM minor field.
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/../../include/ctap_device_version.h" version_lines
    REGEX "^#define CTAP_DEVICE_VERSION_(MAJOR|MINOR|BUILD) [0-9]+$")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/../../include/ctap_device_version.h")
foreach(component MAJOR MINOR BUILD)
    string(REGEX MATCH "CTAP_DEVICE_VERSION_${component} ([0-9]+)" match "${version_lines}")
    set(rom_${component} "${CMAKE_MATCH_1}")
endforeach()
math(EXPR rom_minor "(${rom_MINOR} << 8) | ${rom_BUILD}")
pico_set_binary_version(rp2350_application MAJOR ${rom_MAJOR} MINOR ${rom_minor})
rp2350_configure_image(rp2350_application)
set_source_files_properties(application_main.c ab_boot.c status_led.c usb_transport.c usb_descriptors.c
    presence.c entropy.c board_entropy.c stack_probe.c board_flash.c flash_geometry.c flash_guard.c
    PROPERTIES COMPILE_OPTIONS "-std=c17;-Wall;-Wextra;-Wpedantic;-Werror")

if(RP2350_CORE_LTO)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT ipo_available OUTPUT ipo_reason LANGUAGES C)
    if(NOT ipo_available)
        message(FATAL_ERROR "Core/provider LTO unavailable: ${ipo_reason}")
    endif()
    set_target_properties(ctap_core rp2350_crypto rp2350_mbedcrypto rp2350_ctaes rp2350_monocypher
        PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

option(RP2350_BUILD_PROVISIONING "Expose the explicit RAM-only provisioning tool" OFF)
if(RP2350_BUILD_PROVISIONING)
    add_subdirectory(../../tools/provisioning provisioning)
endif()

option(RP2350_BUILD_RECOVERY "Expose optional RAM recovery tools" OFF)
if(RP2350_BUILD_RECOVERY)
    add_subdirectory(../../tools/recovery recovery)
endif()
