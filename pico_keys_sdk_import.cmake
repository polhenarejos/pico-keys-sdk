#
# This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
# Copyright (c) 2022 Pol Henarejos.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

include(pico-keys-sdk/cmake/version.cmake OPTIONAL)
include(pico-keys-sdk/cmake/options.cmake OPTIONAL)

option(VIDPID "Set specific VID/PID from a known platform {NitroHSM, NitroFIDO2, NitroStart, NitroPro, Nitro3, Yubikey5, YubikeyNeo, YubiHSM, Gnuk, GnuPG}" "None")

message(STATUS "VIDPID:\t\t\t '${VIDPID}'")

if(VIDPID STREQUAL "NitroHSM")
    set(USB_VID 0x20A0)
    set(USB_PID 0x4230)
elseif(VIDPID STREQUAL "NitroFIDO2")
    set(USB_VID 0x20A0)
    set(USB_PID 0x42B1)
elseif(VIDPID STREQUAL "NitroStart")
    set(USB_VID 0x20A0)
    set(USB_PID 0x4211)
elseif(VIDPID STREQUAL "NitroPro")
    set(USB_VID 0x20A0)
    set(USB_PID 0x4108)
elseif(VIDPID STREQUAL "Nitro3")
    set(USB_VID 0x20A0)
    set(USB_PID 0x42B2)
elseif(VIDPID STREQUAL "Yubikey5")
    set(USB_VID 0x1050)
    set(USB_PID 0x0407)
elseif(VIDPID STREQUAL "YubikeyNeo")
    set(USB_VID 0x1050)
    set(USB_PID 0x0116)
elseif(VIDPID STREQUAL "YubiHSM")
    set(USB_VID 0x1050)
    set(USB_PID 0x0030)
elseif(VIDPID STREQUAL "Gnuk")
    set(USB_VID 0x234B)
    set(USB_PID 0x0000)
elseif(VIDPID STREQUAL "GnuPG")
    set(USB_VID 0x1209)
    set(USB_PID 0x2440)
endif()

if(ESP_PLATFORM)
    if(DEFINED CONFIG_TINYUSB_DESC_CUSTOM_VID)
        set(USB_VID CONFIG_TINYUSB_DESC_CUSTOM_VID)
    endif()
    if(DEFINED CONFIG_TINYUSB_DESC_CUSTOM_PID)
        set(USB_PID CONFIG_TINYUSB_DESC_CUSTOM_PID)
    endif()
endif()

if(NOT DEFINED USB_VID)
    set(USB_VID 0x2E8A)
endif()
add_compile_definitions(USB_VID=${USB_VID})

if(NOT DEFINED USB_PID)
    set(USB_PID 0x10FD)
endif()
add_compile_definitions(USB_PID=${USB_PID})

if(NOT DEFINED DEBUG_APDU)
    set(DEBUG_APDU 0)
endif()
if(NOT DEFINED ENABLE_EMULATION)
    set(ENABLE_EMULATION 0)
endif()
include(${CMAKE_CURRENT_LIST_DIR}/cmake/openssl.cmake)

option(ENABLE_DELAYED_BOOT "Enable/disable delayed boot" OFF)
configure_bool_option(
    ENABLE_DELAYED_BOOT
    ""
    "Delayed boot:\t\t enabled"
    "Delayed boot:\t\t disabled"
)
if(ENABLE_DELAYED_BOOT)
    add_compile_definitions(PICO_XOSC_STARTUP_DELAY_MULTIPLIER=64)
endif()
if(USB_ITF_HID)
    add_compile_definitions(USB_ITF_HID=1)
    message(STATUS "USB HID Interface:\t\t enabled")
endif()
if(USB_ITF_CCID)
    add_compile_definitions(USB_ITF_CCID=1)
    message(STATUS "USB CCID Interface:\t\t enabled")
    if(USB_ITF_WCID)
        add_compile_definitions(USB_ITF_WCID=1)
        message(STATUS "USB WebCCID Interface:\t enabled")
    endif()
endif()
add_compile_definitions(DEBUG_APDU=${DEBUG_APDU})
if(NOT ESP_PLATFORM)
    add_compile_definitions(MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_LIST_DIR}/config/mbedtls_config.h")
else()
    add_compile_definitions(CFG_TUSB_CONFIG_FILE="${CMAKE_CURRENT_LIST_DIR}/src/usb/tusb_config.h")
endif()

message(STATUS "USB VID/PID:\t\t\t ${USB_VID}:${USB_PID}")

if(NOT ESP_PLATFORM)
    set(NEED_UPDATE OFF)

    option(ENABLE_EDDSA "Enable/disable EdDSA support" OFF)
    configure_bool_option(
        ENABLE_EDDSA
        ""
        "EdDSA support:\t\t enabled"
        "EdDSA support:\t\t disabled"
    )

    set(MBEDTLS_PATH "${CMAKE_SOURCE_DIR}/pico-keys-sdk/mbedtls")
    execute_process(
        COMMAND git config --global --add safe.directory ${MBEDTLS_PATH}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_QUIET ERROR_QUIET
    )

    if(ENABLE_EDDSA)
        set(MBEDTLS_ORIGIN "https://github.com/polhenarejos/mbedtls.git")
        set(MBEDTLS_REF "mbedtls-3.6-eddsa")

        execute_process(
            COMMAND git -C ${MBEDTLS_PATH} symbolic-ref --quiet --short HEAD
            OUTPUT_VARIABLE CURRENT_BRANCH
            OUTPUT_STRIP_TRAILING_WHITESPACE
            RESULT_VARIABLE BRANCH_ERR
        )

        message(STATUS "Current branch for mbedTLS: ${CURRENT_BRANCH}")
        message(STATUS "Target branch for mbedTLS:  ${MBEDTLS_REF}")

        if(NOT BRANCH_ERR EQUAL 0 OR NOT "${CURRENT_BRANCH}" STREQUAL "${MBEDTLS_REF}")
            set(NEED_UPDATE ON)
        else()
            set(NEED_UPDATE OFF)
        endif()

        add_compile_definitions(
            MBEDTLS_ECP_DP_ED25519_ENABLED=1
            MBEDTLS_ECP_DP_ED448_ENABLED=1
            MBEDTLS_EDDSA_C=1
            MBEDTLS_SHA3_C=1
        )

    else()
        set(MBEDTLS_ORIGIN "https://github.com/Mbed-TLS/mbedtls.git")
        set(MBEDTLS_REF "v3.6.5")

        execute_process(
            COMMAND git -C ${MBEDTLS_PATH} describe --tags --exact-match
            OUTPUT_VARIABLE CURRENT_TAG
            OUTPUT_STRIP_TRAILING_WHITESPACE
            RESULT_VARIABLE TAG_ERR
        )

        message(STATUS "Current tag for mbedTLS: ${CURRENT_TAG}")
        message(STATUS "Target tag for mbedTLS:  ${MBEDTLS_REF}")

        if(NOT TAG_ERR EQUAL 0 OR NOT "${CURRENT_TAG}" STREQUAL "${MBEDTLS_REF}")
            set(NEED_UPDATE ON)
        else()
            set(NEED_UPDATE OFF)
        endif()

    endif()

    if(NEED_UPDATE)
        message(STATUS "Updating mbedTLS source code...")

        execute_process(
            COMMAND git -C ${MBEDTLS_PATH} submodule update --init --recursive --remote pico-keys-sdk
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            OUTPUT_QUIET ERROR_QUIET
        )

        execute_process(
            COMMAND git -C ${MBEDTLS_PATH} remote set-url origin ${MBEDTLS_ORIGIN}
            OUTPUT_QUIET ERROR_QUIET
        )

        execute_process(
            COMMAND git -C ${MBEDTLS_PATH} fetch origin +refs/heads/*:refs/remotes/origin/* --tags --force
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            OUTPUT_QUIET ERROR_QUIET
        )

        execute_process(
            COMMAND rm -rf ${MBEDTLS_PATH}/framework
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            OUTPUT_QUIET ERROR_QUIET
        )

        if(ENABLE_EDDSA)
            execute_process(
                COMMAND git -C ${MBEDTLS_PATH} checkout -B ${MBEDTLS_REF} --track origin/${MBEDTLS_REF}
                WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                OUTPUT_QUIET ERROR_QUIET
            )
        else()
            execute_process(
                COMMAND git -C ${MBEDTLS_PATH} checkout ${MBEDTLS_REF}
                WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                OUTPUT_QUIET ERROR_QUIET
            )
        endif()
    else()
        message(STATUS "mbedTLS source code is up to date.")
    endif()
endif()

option(ENABLE_PQC "Enable/disable PQC support" OFF)
configure_bool_option(
    ENABLE_PQC
    ""
    "PQC support:\t\t\t enabled"
    "PQC support:\t\t\t disabled"
)
if(ENABLE_PQC)
    add_compile_definitions(ENABLE_PQC)
endif()

set(MBEDTLS_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/aes.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/asn1parse.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/asn1write.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/bignum.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/bignum_core.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ccm.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/cmac.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/cipher.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/cipher_wrap.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/constant_time.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ecdsa.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ecdh.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ecp.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ecp_curves.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/gcm.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/hkdf.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/md.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/md5.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/oid.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/pkcs5.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/platform_util.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/rsa.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/rsa_alt_helpers.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/sha1.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/sha256.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/sha512.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/chachapoly.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/chacha20.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/poly1305.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ripemd160.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/des.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/x509write.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/x509write_crt.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/x509_create.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/x509write_csr.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/base64.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/pem.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/pk.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/pk_wrap.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/pkwrite.c
)

if(ENABLE_EDDSA)
    list(APPEND MBEDTLS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/eddsa.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/sha3.c
    )
endif()

if(ENABLE_PQC)
    if(NOT ESP_PLATFORM)
        file(GLOB_RECURSE MLKEM_SOURCES
            ${CMAKE_CURRENT_LIST_DIR}/mlkem/mlkem/src/*.c
        )
        list(FILTER MLKEM_SOURCES EXCLUDE REGEX "/native/")

        add_library(mlkem512 STATIC ${MLKEM_SOURCES})
        target_include_directories(mlkem512 PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/mlkem/mlkem/src
            ${CMAKE_CURRENT_LIST_DIR}/config/mlkem
        )
        target_compile_definitions(mlkem512 PRIVATE
            MLK_CONFIG_PARAMETER_SET=512
            MLK_CONFIG_MULTILEVEL_WITH_SHARED
            MLK_CONFIG_NAMESPACE_PREFIX=mlkem
        )

        add_library(mlkem768 STATIC ${MLKEM_SOURCES})
        target_include_directories(mlkem768 PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/mlkem/mlkem/src
            ${CMAKE_CURRENT_LIST_DIR}/config/mlkem
        )
        target_compile_definitions(mlkem768 PRIVATE
            MLK_CONFIG_PARAMETER_SET=768
            MLK_CONFIG_MULTILEVEL_NO_SHARED
            MLK_CONFIG_NAMESPACE_PREFIX=mlkem
        )

        add_library(mlkem1024 STATIC ${MLKEM_SOURCES})
        target_include_directories(mlkem1024 PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/mlkem/mlkem/src
            ${CMAKE_CURRENT_LIST_DIR}/config/mlkem
        )
        target_compile_definitions(mlkem1024 PRIVATE
            MLK_CONFIG_PARAMETER_SET=1024
            MLK_CONFIG_MULTILEVEL_NO_SHARED
            MLK_CONFIG_NAMESPACE_PREFIX=mlkem
        )
    endif()

    list(APPEND INCLUDES
        ${CMAKE_CURRENT_LIST_DIR}/mlkem/mlkem
        ${CMAKE_CURRENT_LIST_DIR}/config/mlkem
    )
    add_compile_definitions(
        MLK_CONFIG_NAMESPACE_PREFIX=mlkem
        MLK_CONFIG_MULTILEVEL_BUILD=1
    )
endif()

list(APPEND PICO_KEYS_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/src/main.c
    ${CMAKE_CURRENT_LIST_DIR}/src/usb/usb.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fs/file.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fs/flash.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fs/low_flash.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fs/otp.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fs/phy.c
    ${CMAKE_CURRENT_LIST_DIR}/src/rng/random.c
    ${CMAKE_CURRENT_LIST_DIR}/src/rng/hwrng.c
    ${CMAKE_CURRENT_LIST_DIR}/src/eac.c
    ${CMAKE_CURRENT_LIST_DIR}/src/crypto_utils.c
    ${CMAKE_CURRENT_LIST_DIR}/src/asn1.c
    ${CMAKE_CURRENT_LIST_DIR}/src/apdu.c
    ${CMAKE_CURRENT_LIST_DIR}/src/rescue.c
    ${CMAKE_CURRENT_LIST_DIR}/src/led/led.c
)

if(ESP_PLATFORM)
    list(APPEND PICO_KEYS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/led/led_neopixel.c
        ${CMAKE_CURRENT_LIST_DIR}/src/led/led_pico.c
    )
else()
    if(NOT ENABLE_EMULATION)
        list(APPEND PICO_KEYS_SOURCES
            ${CMAKE_CURRENT_LIST_DIR}/src/led/led_cyw43.c
            ${CMAKE_CURRENT_LIST_DIR}/src/led/led_pico.c
            ${CMAKE_CURRENT_LIST_DIR}/src/led/led_pimoroni.c
            ${CMAKE_CURRENT_LIST_DIR}/src/led/led_ws2812.c
        )
    endif()
endif()

## mbedTLS reports an stringop overflow for cmac.c
if(NOT ENABLE_EMULATION AND NOT APPLE)
    set_source_files_properties(
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/cmac.c
        PROPERTIES
        COMPILE_FLAGS "-Wno-error=stringop-overflow= -Wno-stringop-overflow"
    )
endif()
list(APPEND INCLUDES
    ${CMAKE_CURRENT_LIST_DIR}/src
    ${CMAKE_CURRENT_LIST_DIR}/src/usb
    ${CMAKE_CURRENT_LIST_DIR}/src/fs
    ${CMAKE_CURRENT_LIST_DIR}/src/rng
    ${CMAKE_CURRENT_LIST_DIR}/src/led
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/include
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library
)

if(USB_ITF_HID)
    list(APPEND MBEDTLS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/x509write_crt.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/x509_create.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/x509write_csr.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/pk.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/pk_wrap.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/pkwrite.c
    )
endif()

set(CBOR_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/tinycbor/src/cborencoder.c
    ${CMAKE_CURRENT_LIST_DIR}/tinycbor/src/cborparser.c
    ${CMAKE_CURRENT_LIST_DIR}/tinycbor/src/cborparser_dup_string.c
)

list(APPEND INCLUDES
    ${CMAKE_CURRENT_LIST_DIR}/tinycbor/src
)

set(LIBRARIES)
if(NOT SKIP_MBEDTLS_FOR_OPENSSL_EMULATION)
    list(APPEND LIBRARIES mbedtls)
endif()
if(USE_OPENSSL_EMULATION_WRAPPER)
    list(APPEND LIBRARIES OpenSSL::Crypto)
endif()

if(NOT ESP_PLATFORM)
    if(NOT SKIP_MBEDTLS_FOR_OPENSSL_EMULATION)
        add_library(mbedtls STATIC ${MBEDTLS_SOURCES})
        target_include_directories(mbedtls PUBLIC ${CMAKE_CURRENT_LIST_DIR}/mbedtls/include)
    endif()
    if(USB_ITF_HID)
        add_library(tinycbor STATIC ${CBOR_SOURCES})
        target_include_directories(tinycbor PUBLIC ${CMAKE_CURRENT_LIST_DIR}/tinycbor/src)
        list(APPEND LIBRARIES tinycbor)
    endif()
endif()

if(PICO_PLATFORM)
    list(APPEND LIBRARIES
        pico_stdlib
        pico_multicore
        pico_rand
        pico_aon_timer
        hardware_flash
        pico_unique_id
        tinyusb_device
        tinyusb_board
        hardware_pio
    )
endif()

if(ENABLE_PQC)
    list(APPEND LIBRARIES
        mlkem768
        mlkem1024
        mlkem512
    )
endif()

set(IS_CYW43 0)
if(PICO_PLATFORM)
    file(READ ${PICO_SDK_PATH}/src/boards/include/boards/${PICO_BOARD}.h content)
    string(REGEX MATCHALL "CYW43_WL_GPIO_LED_PIN" _ ${content})
    if(CMAKE_MATCH_0)
        message(STATUS "Found cyw43 LED:\t\t true")
        list(APPEND LIBRARIES pico_cyw43_arch_none)
        set(IS_CYW43 1)
    endif()
endif()

function(add_impl_library target)
    add_library(${target} INTERFACE)
    string(TOUPPER ${target} TARGET_UPPER)
    target_compile_definitions(${target} INTERFACE LIB_${TARGET_UPPER}=1)
endfunction()

# Apply strict warning flags to a caller-provided source list.
# Usage:
#   pico_keys_apply_strict_flags(SOURCES ${SOURCES} FILTER_REGEX "/src/fido/")
function(pico_keys_apply_strict_flags)
    set(options)
    set(oneValueArgs FILTER_REGEX)
    set(multiValueArgs SOURCES)
    cmake_parse_arguments(PKAS "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT PKAS_SOURCES)
        return()
    endif()

    set(PICO_KEYS_STRICT_FLAGS
        -Wextra
        -pipe
        -funsigned-char
        -fstrict-aliasing
        -Wchar-subscripts
        -Wundef
        -Wshadow
        -Wcast-align
        -Wwrite-strings
        -Wunused
        -Wuninitialized
        -Wpointer-arith
        -Wredundant-decls
        -Winline
        -Wformat
        -Wformat-security
        -Wswitch-enum
        -Winit-self
        -Wmissing-include-dirs
        -Wempty-body
        -fdiagnostics-color=auto
        -Wmissing-prototypes
        -Wstrict-prototypes
        -Wold-style-definition
        -Wbad-function-cast
        -Wnested-externs
        -Wmissing-declarations
        -Werror
    )

    foreach(src IN LISTS PKAS_SOURCES)
        if(PKAS_FILTER_REGEX)
            if(NOT src MATCHES "${PKAS_FILTER_REGEX}")
                continue()
            endif()
        endif()
        set_property(SOURCE "${src}" APPEND PROPERTY COMPILE_OPTIONS ${PICO_KEYS_STRICT_FLAGS})
    endforeach()
endfunction()

if(USB_ITF_HID)
    list(APPEND PICO_KEYS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/hid/hid.c
    )
    list(APPEND INCLUDES
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/hid
    )
endif()

if(USB_ITF_CCID)
    list(APPEND PICO_KEYS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/ccid/ccid.c
    )
    list(APPEND INCLUDES
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/ccid
    )
endif()

if(NOT MSVC)
    add_compile_options("-fmacro-prefix-map=${CMAKE_CURRENT_LIST_DIR}/=")
endif()
if(MSVC)
    list(APPEND PICO_KEYS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/mman.c
    )
endif()
if(ENABLE_EMULATION)
    if(APPLE)
        add_definitions("-Wno-deprecated-declarations")
    endif()
    add_compile_definitions(ENABLE_EMULATION)
    list(APPEND PICO_KEYS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/emulation/emulation.c
    )
    if(USE_OPENSSL_EMULATION_WRAPPER)
        list(APPEND PICO_KEYS_SOURCES
            ${CMAKE_CURRENT_LIST_DIR}/src/usb/emulation/openssl.c
        )
    endif()
    list(APPEND MBEDTLS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/aesni.c
    )
    list(APPEND INCLUDES
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/emulation
    )
else()
    list(APPEND PICO_KEYS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/usb_descriptors.c
    )
endif()

if(MSVC)
    set(
        CMAKE_C_FLAGS
        "${CMAKE_C_FLAGS} -wd4820 -wd4255 -wd5045 -wd4706 -wd4061 -wd5105 -wd4141 -wd4200"
    )

    add_compile_definitions(
        _CRT_SECURE_NO_WARNINGS
        __STDC_WANT_SECURE_LIB__=0
        _WIN32_WINNT_WIN10_TH2=0
        _WIN32_WINNT_WIN10_RS1=0
        _WIN32_WINNT_WIN10_RS2=0
        _WIN32_WINNT_WIN10_RS3=0
        _WIN32_WINNT_WIN10_RS4=0
        _WIN32_WINNT_WIN10_RS5=0
        _STRALIGN_USE_SECURE_CRT=0
        NTDDI_WIN11_DT=0
    )
endif()

if(PICO_PLATFORM)
    pico_sdk_init()
endif()

if(PICO_RP2350)
    pico_set_uf2_family(${CMAKE_PROJECT_NAME} "rp2350-arm-s")
    pico_embed_pt_in_binary(${CMAKE_PROJECT_NAME} "${CMAKE_CURRENT_LIST_DIR}/config/rp2350/pt.json")
    if(NOT IS_CYW43)
        pico_set_binary_type(${CMAKE_PROJECT_NAME} copy_to_ram)
    endif()
    if(SECURE_BOOT_PKEY)
        message(STATUS "Secure Boot Key ${SECURE_BOOT_PKEY}")
        pico_sign_binary(${CMAKE_PROJECT_NAME} ${SECURE_BOOT_PKEY})
        pico_hash_binary(${CMAKE_PROJECT_NAME})
    endif()
    target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE pico_bootrom)

    list(APPEND INCLUDES
        ${CMAKE_CURRENT_LIST_DIR}/config/rp2350/alt
    )
    if(TARGET mbedtls)
        target_include_directories(mbedtls PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/config/rp2350/alt
        )
        target_link_libraries(mbedtls PRIVATE pico_sha256)
    endif()
    list(APPEND PICO_KEYS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/config/rp2350/alt/sha256_alt.c
    )
    add_compile_definitions(MBEDTLS_SHA256_ALT=1)
    list(APPEND LIBRARIES pico_sha256)
endif()
set(INTERNAL_SOURCES ${PICO_KEYS_SOURCES})

if(NOT TARGET pico_keys_sdk)
    if(PICO_PLATFORM)
        pico_add_library(pico_keys_sdk)

        target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ${LIBRARIES})
    else()
        add_impl_library(pico_keys_sdk)
    endif()
    target_sources(pico_keys_sdk INTERFACE ${PICO_KEYS_SOURCES})
    target_include_directories(pico_keys_sdk INTERFACE ${INCLUDES})
    target_link_libraries(pico_keys_sdk INTERFACE ${LIBRARIES})
endif()
