cmake_minimum_required(VERSION 3.21)
project(ctap_core VERSION 0.1.0 LANGUAGES C)

# Embed with add_subdirectory() and link ctap_core. The application supplies
# clock, touch, crypto and storage callbacks; this target has no platform drivers.
add_library(ctap_core STATIC
    src/authenticator/auth_credentials.c
    src/authenticator/auth_es256.c
    src/authenticator/auth_pin.c
    src/authenticator/auth_platform.c
    src/authenticator/auth_secret_crypto.c
    src/authenticator/auth_text.c
    src/ctap/cbor_reader.c
    src/ctap/cbor_writer.c
    src/ctap/ctap.c
    src/ctap/ctap_attestation.c
    src/ctap/ctap_client_pin.c
    src/ctap/ctap_credential_management.c
    src/ctap/ctap_entities.c
    src/ctap/ctap_get_assertion.c
    src/ctap/ctap_get_info.c
    src/ctap/ctap_hmac_secret.c
    src/ctap/ctap_make_credential.c
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
set_target_properties(ctap_core PROPERTIES C_EXTENSIONS OFF)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(ctap_core PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

# Off by default when included in firmware. Native tests require only a C host
# compiler and the standard library, not a client, OS provider or USB integration.
if(PROJECT_IS_TOP_LEVEL)
    include(CTest)
else()
    option(BUILD_TESTING "Build portable native core tests" OFF)
endif()
if(BUILD_TESTING)
    enable_testing()
    foreach(suite IN ITEMS
        auth_credentials ctap_client_pin ctap_get_assertion ctap_get_info
        ctap_hmac_secret ctap_make_credential ctap_reset ctap_user_presence
        ctaphid ctaphid_channels ctaphid_device ctaphid_init ctaphid_ping
        ctaphid_response ctaphid_wink_msg resident_credentials ctap_conformance)
        add_executable(test_${suite} tests/test_${suite}.c)
        target_link_libraries(test_${suite} PRIVATE ctap_core)
        set_target_properties(test_${suite} PROPERTIES C_EXTENSIONS OFF)
        if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
            # Test assertions perform operations; keep them in Release builds.
            target_compile_options(test_${suite} PRIVATE -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
        endif()
        add_test(NAME ${suite} COMMAND test_${suite})
    endforeach()
endif()
