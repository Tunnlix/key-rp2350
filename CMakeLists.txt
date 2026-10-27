cmake_minimum_required(VERSION 3.21)
project(ctap_core VERSION 0.1.0 LANGUAGES C)

# Embed with add_subdirectory() and link ctap_core. The application supplies
# clock, touch, crypto and storage callbacks; this target has no platform drivers.
add_library(ctap_core STATIC
    src/authenticator/auth_credentials.c
    src/authenticator/auth_nonresident.c
    src/authenticator/auth_resident.c
    src/authenticator/auth_es256.c
    src/authenticator/auth_pin.c
    src/authenticator/auth_platform.c
    src/authenticator/auth_secret_crypto.c
    src/authenticator/auth_text.c
    src/ctap/cbor_reader.c
    src/ctap/cbor_writer.c
    src/ctap/ctap.c
    src/ctap/ctap_attestation.c
    src/ctap/ctap_authenticator_config.c
    src/ctap/ctap_large_blobs.c
    src/ctap/ctap_client_pin.c
    src/ctap/ctap_credential_management.c
    src/ctap/ctap_entities.c
    src/ctap/ctap_get_assertion.c
    src/ctap/ctap_get_assertion_prepare.c
    src/ctap/ctap_get_info.c
    src/ctap/ctap_hmac_secret.c
    src/ctap/ctap_make_credential.c
    src/ctap/ctap_make_credential_finish.c
    src/ctap/ctap_pin_protocol.c
    src/ctap/ctap_request.c
    src/ctap/ctap_reset.c
    src/ctap/ctap_user_presence.c
    src/protocol/ctaphid_channels.c
    src/protocol/ctaphid_ctap_backend.c
    src/protocol/ctaphid_device.c
    src/protocol/ctaphid_dispatcher.c
    src/protocol/ctaphid_handlers.c
    src/protocol/ctaphid_parser.c
    src/protocol/ctaphid_reassembler.c
    src/protocol/ctaphid_response.c
)
target_include_directories(ctap_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_features(ctap_core PUBLIC c_std_17)
# Empty cache values retain the defaults in ctap_config.h. PUBLIC definitions
# keep application/provider struct layouts consistent with the library.
foreach(setting IN ITEMS CTAP_MESSAGE_CAPACITY CTAP_RESIDENT_CAPACITY CTAP_TOUCH_TIMEOUT_MS)
    set(${setting} "" CACHE STRING "Override ${setting} from ctap_config.h")
    if(NOT "${${setting}}" STREQUAL "")
        if(NOT "${${setting}}" MATCHES "^[1-9][0-9]*$")
            message(FATAL_ERROR "${setting} must be a positive integer")
        endif()
        target_compile_definitions(ctap_core PUBLIC ${setting}=${${setting}})
    endif()
endforeach()
set_target_properties(ctap_core PROPERTIES C_EXTENSIONS OFF)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(ctap_core PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

# Per-function regression limits for modules with caller-owned scratch.
# This is not a bound on a complete call chain or on provider/interrupt stack.
set(CTAP_CM_STACK_BUDGET 1024 CACHE STRING "Credential-management stack bytes per function (GCC)")
set(CTAP_CREDENTIALS_STACK_BUDGET 512 CACHE STRING "Credential lookup/mutation stack bytes per function (GCC)")
set(CTAP_RESIDENT_STACK_BUDGET 512 CACHE STRING "Resident-creation stack bytes per function (GCC)")
set(CTAP_NONRESIDENT_STACK_BUDGET 512 CACHE STRING "Non-resident creation stack bytes per function (GCC)")
set(CTAP_GA_FINISH_STACK_BUDGET 512 CACHE STRING "Assertion finish stack bytes per function (GCC)")
set(CTAP_GA_PREPARE_STACK_BUDGET 1024 CACHE STRING "Assertion preparation stack bytes per function (GCC)")
set(CTAP_MC_PREPARE_STACK_BUDGET 1024 CACHE STRING "Registration preparation stack bytes per function (GCC)")
set(CTAP_MC_FINISH_STACK_BUDGET 512 CACHE STRING "Registration finish stack bytes per function (GCC)")
option(CTAP_STACK_BUDGET_CHECKS "Enforce per-function GCC stack budgets in ordinary builds" ON)
if(NOT CTAP_CM_STACK_BUDGET MATCHES "^[1-9][0-9]*$")
    message(FATAL_ERROR "CTAP_CM_STACK_BUDGET must be a positive integer")
endif()
if(NOT CTAP_RESIDENT_STACK_BUDGET MATCHES "^[1-9][0-9]*$")
    message(FATAL_ERROR "CTAP_RESIDENT_STACK_BUDGET must be a positive integer")
endif()
if(NOT CTAP_GA_FINISH_STACK_BUDGET MATCHES "^[1-9][0-9]*$")
    message(FATAL_ERROR "CTAP_GA_FINISH_STACK_BUDGET must be a positive integer")
endif()
if(NOT CTAP_GA_PREPARE_STACK_BUDGET MATCHES "^[1-9][0-9]*$")
    message(FATAL_ERROR "CTAP_GA_PREPARE_STACK_BUDGET must be a positive integer")
endif()
if(NOT CTAP_MC_PREPARE_STACK_BUDGET MATCHES "^[1-9][0-9]*$")
    message(FATAL_ERROR "CTAP_MC_PREPARE_STACK_BUDGET must be a positive integer")
endif()
if(NOT CTAP_MC_FINISH_STACK_BUDGET MATCHES "^[1-9][0-9]*$")
    message(FATAL_ERROR "CTAP_MC_FINISH_STACK_BUDGET must be a positive integer")
endif()
if(NOT CTAP_NONRESIDENT_STACK_BUDGET MATCHES "^[1-9][0-9]*$")
    message(FATAL_ERROR "CTAP_NONRESIDENT_STACK_BUDGET must be a positive integer")
endif()
if(NOT CTAP_CREDENTIALS_STACK_BUDGET MATCHES "^[1-9][0-9]*$")
    message(FATAL_ERROR "CTAP_CREDENTIALS_STACK_BUDGET must be a positive integer")
endif()
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CTAP_STACK_BUDGET_CHECKS)
    target_compile_options(ctap_core PRIVATE -fstack-usage)
    set_source_files_properties(src/authenticator/auth_credentials.c PROPERTIES
        COMPILE_OPTIONS "-Wstack-usage=${CTAP_CREDENTIALS_STACK_BUDGET}")
    set_source_files_properties(src/ctap/ctap_credential_management.c PROPERTIES
        COMPILE_OPTIONS "-Wstack-usage=${CTAP_CM_STACK_BUDGET}")
    set_source_files_properties(src/authenticator/auth_resident.c PROPERTIES
        COMPILE_OPTIONS "-Wstack-usage=${CTAP_RESIDENT_STACK_BUDGET}")
    set_source_files_properties(src/authenticator/auth_nonresident.c PROPERTIES
        COMPILE_OPTIONS "-Wstack-usage=${CTAP_NONRESIDENT_STACK_BUDGET}")
    set_source_files_properties(src/ctap/ctap_get_assertion.c PROPERTIES
        COMPILE_OPTIONS "-Wstack-usage=${CTAP_GA_FINISH_STACK_BUDGET}")
    set_source_files_properties(src/ctap/ctap_get_assertion_prepare.c PROPERTIES
        COMPILE_OPTIONS "-Wstack-usage=${CTAP_GA_PREPARE_STACK_BUDGET}")
    set_source_files_properties(src/ctap/ctap_make_credential.c PROPERTIES
        COMPILE_OPTIONS "-Wstack-usage=${CTAP_MC_PREPARE_STACK_BUDGET}")
    set_source_files_properties(src/ctap/ctap_make_credential_finish.c PROPERTIES
        COMPILE_OPTIONS "-Wstack-usage=${CTAP_MC_FINISH_STACK_BUDGET}")
elseif(NOT CTAP_STACK_BUDGET_CHECKS)
    message(STATUS "Per-function stack budget diagnostics explicitly disabled; use ordinary builds for stack reports")
else()
    message(STATUS "Stack budget check unavailable with ${CMAKE_C_COMPILER_ID}; use a GCC build for stack reports")
endif()
