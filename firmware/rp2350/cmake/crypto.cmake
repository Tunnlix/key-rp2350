# Same pinned C implementation/configuration in native tests and target image.
if(NOT RP2350_MBEDTLS_PATH)
    # The SDK's 3.6.6 has CVE-2026-54435 in the enabled P-256 reduction path.
    # Fetch verified sources only: our bounded configuration selects the units
    # below, not upstream's default TLS/program/test targets. A local reviewed
    # 3.6.7 tree can be supplied for offline builds.
    include(FetchContent)
    if(POLICY CMP0135)
        cmake_policy(SET CMP0135 NEW)
    endif()
    FetchContent_Declare(tunnixkey_mbedtls
        URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2
        URL_HASH SHA256=a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6
        SOURCE_SUBDIR _tunnixkey_sources_only)
    FetchContent_MakeAvailable(tunnixkey_mbedtls)
    set(RP2350_MBEDTLS_PATH "${tunnixkey_mbedtls_SOURCE_DIR}" CACHE PATH "Reviewed Mbed TLS 3.6.7 source tree" FORCE)
endif()
if(NOT EXISTS "${RP2350_MBEDTLS_PATH}/include/mbedtls/build_info.h")
    message(FATAL_ERROR "Set RP2350_MBEDTLS_PATH to reviewed Mbed TLS 3.6.7, or clear it to fetch verified sources")
endif()
file(READ "${RP2350_MBEDTLS_PATH}/include/mbedtls/build_info.h" crypto_version)
if(NOT crypto_version MATCHES "MBEDTLS_VERSION_STRING +\"3\\.6\\.7\"")
    message(FATAL_ERROR "Provider requires Mbed TLS 3.6.7 (3.6.6 has CVE-2026-54435); clear RP2350_MBEDTLS_PATH to fetch it")
endif()
set(crypto_dir "${CMAKE_CURRENT_LIST_DIR}/..")
add_library(rp2350_crypto STATIC "${crypto_dir}/crypto.c")
set_target_properties(rp2350_crypto PROPERTIES C_STANDARD 17 C_EXTENSIONS OFF)
target_include_directories(rp2350_crypto PUBLIC "${crypto_dir}")
target_link_libraries(rp2350_crypto PUBLIC ctap_core)
target_compile_options(rp2350_crypto PRIVATE -Wall -Wextra -Wpedantic -Werror -fstack-usage)
add_library(rp2350_mbedcrypto STATIC)
foreach(unit IN ITEMS asn1parse asn1write bignum bignum_core bignum_mod
        bignum_mod_raw constant_time ecdh ecdsa ecp ecp_curves ecp_curves_new
        hmac_drbg md memory_buffer_alloc platform platform_util sha256)
    target_sources(rp2350_mbedcrypto PRIVATE "${RP2350_MBEDTLS_PATH}/library/${unit}.c")
endforeach()
target_include_directories(rp2350_mbedcrypto SYSTEM PUBLIC "${RP2350_MBEDTLS_PATH}/include")
target_include_directories(rp2350_mbedcrypto PRIVATE "${RP2350_MBEDTLS_PATH}/library" "${crypto_dir}")
target_compile_definitions(rp2350_mbedcrypto PUBLIC MBEDTLS_CONFIG_FILE="crypto_config.h")
target_include_directories(rp2350_mbedcrypto PUBLIC "${crypto_dir}")
target_compile_options(rp2350_mbedcrypto PRIVATE -fstack-usage -ffunction-sections -fdata-sections)
target_link_libraries(rp2350_crypto PUBLIC rp2350_mbedcrypto)
add_library(rp2350_ctaes STATIC "${crypto_dir}/vendor/ctaes/ctaes.c")
set_target_properties(rp2350_ctaes PROPERTIES C_STANDARD 17 C_EXTENSIONS OFF)
target_include_directories(rp2350_ctaes PUBLIC "${crypto_dir}/vendor/ctaes")
target_compile_options(rp2350_ctaes PRIVATE -Wall -Wextra -Wpedantic -Werror
    -fstack-usage -ffunction-sections -fdata-sections)
target_link_libraries(rp2350_crypto PRIVATE rp2350_ctaes)

# PureEd25519 only; no alternate RNG, heap or key storage is introduced.
add_library(rp2350_monocypher STATIC
    "${crypto_dir}/vendor/monocypher/monocypher.c"
    "${crypto_dir}/vendor/monocypher/monocypher-ed25519.c")
set_target_properties(rp2350_monocypher PROPERTIES C_STANDARD 17 C_EXTENSIONS OFF)
target_include_directories(rp2350_monocypher PUBLIC "${crypto_dir}/vendor/monocypher")
target_compile_options(rp2350_monocypher PRIVATE -Wall -Wextra -Wpedantic -Werror
    -fstack-usage -ffunction-sections -fdata-sections)
target_link_libraries(rp2350_crypto PRIVATE rp2350_monocypher)
