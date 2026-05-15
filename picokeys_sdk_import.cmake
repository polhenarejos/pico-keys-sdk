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
include(${CMAKE_CURRENT_LIST_DIR}/cmake/build_helpers.cmake)

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
if(USB_ITF_LWIP)
    add_compile_definitions(USB_ITF_LWIP=1)
    message(STATUS "USB LWIP Interface:\t\t enabled")
endif()
add_compile_definitions(DEBUG_APDU=${DEBUG_APDU})
if(NOT ESP_PLATFORM)
    add_compile_definitions(MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_LIST_DIR}/config/mbedtls_config.h")
else()
    add_compile_definitions(CFG_TUSB_CONFIG_FILE="${CMAKE_CURRENT_LIST_DIR}/src/usb/tusb_config.h")
endif()

message(STATUS "USB VID/PID:\t\t\t ${USB_VID}:${USB_PID}")
include(${CMAKE_CURRENT_LIST_DIR}/cmake/deps.cmake)

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
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/aes.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/asn1parse.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/asn1write.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/bignum.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/bignum_core.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/ccm.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/cmac.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/cipher.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/cipher_wrap.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/constant_time.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/ecdsa.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/ecdh.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/ecp.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/ecp_curves.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/gcm.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/hkdf.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/md.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/md5.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/oid.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/pkcs5.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/platform_util.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/rsa.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/rsa_alt_helpers.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/sha1.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/sha256.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/sha512.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/chachapoly.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/chacha20.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/poly1305.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/ripemd160.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/des.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/x509write.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/x509write_crt.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/x509_create.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/x509write_csr.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/base64.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/pem.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/pk.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/pk_wrap.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/pkwrite.c
)

if(ENABLE_EDDSA)
    list(APPEND MBEDTLS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/eddsa.c
        ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/sha3.c
    )
endif()

if(ENABLE_PQC)
    if(NOT ESP_PLATFORM)
        file(GLOB_RECURSE MLKEM_SOURCES
            ${CMAKE_CURRENT_LIST_DIR}/third-party/mlkem/mlkem/src/*.c
        )
        list(FILTER MLKEM_SOURCES EXCLUDE REGEX "/native/")

        add_library(mlkem512 STATIC ${MLKEM_SOURCES})
        target_include_directories(mlkem512 PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/third-party/mlkem/mlkem/src
            ${CMAKE_CURRENT_LIST_DIR}/config/mlkem
        )
        target_compile_definitions(mlkem512 PRIVATE
            MLK_CONFIG_PARAMETER_SET=512
            MLK_CONFIG_MULTILEVEL_WITH_SHARED
            MLK_CONFIG_NAMESPACE_PREFIX=mlkem
        )

        add_library(mlkem768 STATIC ${MLKEM_SOURCES})
        target_include_directories(mlkem768 PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/third-party/mlkem/mlkem/src
            ${CMAKE_CURRENT_LIST_DIR}/config/mlkem
        )
        target_compile_definitions(mlkem768 PRIVATE
            MLK_CONFIG_PARAMETER_SET=768
            MLK_CONFIG_MULTILEVEL_NO_SHARED
            MLK_CONFIG_NAMESPACE_PREFIX=mlkem
        )

        add_library(mlkem1024 STATIC ${MLKEM_SOURCES})
        target_include_directories(mlkem1024 PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/third-party/mlkem/mlkem/src
            ${CMAKE_CURRENT_LIST_DIR}/config/mlkem
        )
        target_compile_definitions(mlkem1024 PRIVATE
            MLK_CONFIG_PARAMETER_SET=1024
            MLK_CONFIG_MULTILEVEL_NO_SHARED
            MLK_CONFIG_NAMESPACE_PREFIX=mlkem
        )

        file(GLOB_RECURSE MLDSA_SOURCES
            ${CMAKE_CURRENT_LIST_DIR}/third-party/mldsa/mldsa/src/*.c
        )
        list(FILTER MLDSA_SOURCES EXCLUDE REGEX "/native/")

        add_library(mldsa44 STATIC ${MLDSA_SOURCES})
        target_include_directories(mldsa44 PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/third-party/mldsa/mldsa/src
            ${CMAKE_CURRENT_LIST_DIR}/config/mldsa
        )
        target_compile_definitions(mldsa44 PRIVATE
            MLD_CONFIG_PARAMETER_SET=44
            MLD_CONFIG_MULTILEVEL_WITH_SHARED
            MLD_CONFIG_NAMESPACE_PREFIX=mldsa
        )

        add_library(mldsa65 STATIC ${MLDSA_SOURCES})
        target_include_directories(mldsa65 PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/third-party/mldsa/mldsa/src
            ${CMAKE_CURRENT_LIST_DIR}/config/mldsa
        )
        target_compile_definitions(mldsa65 PRIVATE
            MLD_CONFIG_PARAMETER_SET=65
            MLD_CONFIG_MULTILEVEL_NO_SHARED
            MLD_CONFIG_NAMESPACE_PREFIX=mldsa
        )

        add_library(mldsa87 STATIC ${MLDSA_SOURCES})
        target_include_directories(mldsa87 PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/third-party/mldsa/mldsa/src
            ${CMAKE_CURRENT_LIST_DIR}/config/mldsa
        )
        target_compile_definitions(mldsa87 PRIVATE
            MLD_CONFIG_PARAMETER_SET=87
            MLD_CONFIG_MULTILEVEL_NO_SHARED
            MLD_CONFIG_NAMESPACE_PREFIX=mldsa
        )
    endif()

    list(APPEND INCLUDES
        ${CMAKE_CURRENT_LIST_DIR}/third-party/mlkem/mlkem
        ${CMAKE_CURRENT_LIST_DIR}/config/mlkem
        ${CMAKE_CURRENT_LIST_DIR}/third-party/mldsa/mldsa
        ${CMAKE_CURRENT_LIST_DIR}/config/mldsa
    )
    list(APPEND SYSTEM_INCLUDES
        ${CMAKE_CURRENT_LIST_DIR}/third-party/mlkem/mlkem
        ${CMAKE_CURRENT_LIST_DIR}/config/mlkem
        ${CMAKE_CURRENT_LIST_DIR}/third-party/mldsa/mldsa
        ${CMAKE_CURRENT_LIST_DIR}/config/mldsa
    )
    add_compile_definitions(
        MLK_CONFIG_NAMESPACE_PREFIX=mlkem
        MLK_CONFIG_MULTILEVEL_BUILD=1
        MLD_CONFIG_NAMESPACE_PREFIX=mldsa
        MLD_CONFIG_MULTILEVEL_BUILD=1
    )
endif()

if(ESP_PLATFORM)
    list(APPEND PICOKEYS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/otp/otp_esp32.c
    )
elseif(ENABLE_EMULATION)
    if(MSVC)
        list(APPEND PICOKEYS_SOURCES
            ${CMAKE_CURRENT_LIST_DIR}/src/otp/otp_windows.c
        )
    elseif(APPLE)
        list(APPEND PICOKEYS_SOURCES
            ${CMAKE_CURRENT_LIST_DIR}/src/otp/otp_macos.c
        )
    elseif(UNIX AND NOT APPLE)
        add_compile_definitions(OTP_LINUX_USE_TSS=1)
        list(APPEND PICOKEYS_SOURCES
            ${CMAKE_CURRENT_LIST_DIR}/src/otp/otp_linux.c
        )
    else()
        list(APPEND PICOKEYS_SOURCES
            ${CMAKE_CURRENT_LIST_DIR}/src/otp/otp_emulation.c
        )
    endif()
elseif(PICO_RP2350)
    list(APPEND PICOKEYS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/otp/otp_rp2350.c
    )
elseif(PICO_RP2040)
    list(APPEND PICOKEYS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/otp/otp_rp2040.c
    )
endif()

list(APPEND PICOKEYS_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/src/main.c
    ${CMAKE_CURRENT_LIST_DIR}/src/usb/usb.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fs/file.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fs/flash.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fs/low_flash.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fs/phy.c
    ${CMAKE_CURRENT_LIST_DIR}/src/otp/otp.c
    ${CMAKE_CURRENT_LIST_DIR}/src/rng/random.c
    ${CMAKE_CURRENT_LIST_DIR}/src/rng/hwrng.c
    ${CMAKE_CURRENT_LIST_DIR}/src/eac.c
    ${CMAKE_CURRENT_LIST_DIR}/src/crypto_utils.c
    ${CMAKE_CURRENT_LIST_DIR}/src/asn1.c
    ${CMAKE_CURRENT_LIST_DIR}/src/apdu.c
    ${CMAKE_CURRENT_LIST_DIR}/src/rescue.c
    ${CMAKE_CURRENT_LIST_DIR}/src/serial.c
    ${CMAKE_CURRENT_LIST_DIR}/src/pico_time.c
    ${CMAKE_CURRENT_LIST_DIR}/src/button.c
    ${CMAKE_CURRENT_LIST_DIR}/src/led/led.c
)

if(ESP_PLATFORM)
    list(APPEND PICOKEYS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/led/led_neopixel.c
        ${CMAKE_CURRENT_LIST_DIR}/src/led/led_pico.c
    )
else()
    if(NOT ENABLE_EMULATION)
        list(APPEND PICOKEYS_SOURCES
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
        ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/cmac.c
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
    ${CMAKE_CURRENT_LIST_DIR}/src/otp
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library
)
set(SYSTEM_INCLUDES
    ${SYSTEM_INCLUDES}
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/include
)
if(USB_ITF_HID)
    list(APPEND SYSTEM_INCLUDES
        ${CMAKE_CURRENT_LIST_DIR}/third-party/tinycbor/src
    )
endif()
if(USB_ITF_LWIP)
    list(APPEND SYSTEM_INCLUDES
        ${CMAKE_CURRENT_LIST_DIR}/third-party/cjson
    )
endif()

if(USB_ITF_LWIP)
    if (NOT ESP_PLATFORM)
        add_compile_definitions(
            MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
            MBEDTLS_SSL_PROTO_TLS1_2
            MBEDTLS_SSL_SRV_C
            MBEDTLS_SSL_TLS_C
        )
    endif()
    list(APPEND MBEDTLS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/pkparse.c
        ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/pk_ecc.c
        ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/pkcs12.c
        ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/ssl_ciphersuites.c
        ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/ssl_msg.c
        ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/ssl_tls.c
        ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/ssl_tls12_server.c
        ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/x509.c
        ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/x509_crt.c
    )
endif()
if(USB_ITF_HID)
    list(APPEND MBEDTLS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/x509write_crt.c
        ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/x509_create.c
        ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/x509write_csr.c
        ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/pk.c
        ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/pk_wrap.c
        ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/pkwrite.c
    )
endif()

set(CBOR_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/third-party/tinycbor/src/cborencoder.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/tinycbor/src/cborparser.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/tinycbor/src/cborparser_dup_string.c
)

set(CJSON_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/third-party/cjson/cJSON.c
)

set(LIBCVC_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/third-party/libcvc/src/cvc_build.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/libcvc/src/cvc_parse.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/libcvc/src/cvc_sign.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/libcvc/src/cvc_tlv.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/libcvc/src/cvc_write.c
)

set(LIBRARIES)
if(NOT SKIP_MBEDTLS_FOR_OPENSSL_EMULATION)
    list(APPEND LIBRARIES mbedtls)
endif()
if(USE_OPENSSL_EMULATION_WRAPPER)
    list(APPEND LIBRARIES OpenSSL::Crypto)
endif()

if(UNIX AND NOT APPLE AND ENABLE_EMULATION)
    find_library(TSS2_ESYS_LIB NAMES tss2-esys)
    find_library(TSS2_TCTILDR_LIB NAMES tss2-tctildr)
    if(TSS2_ESYS_LIB AND TSS2_TCTILDR_LIB)
        list(APPEND LIBRARIES ${TSS2_ESYS_LIB} ${TSS2_TCTILDR_LIB})
    else()
        message(WARNING "Linux OTP TPM backend enabled but tpm2-tss libraries not found (need tss2-esys and tss2-tctildr)")
    endif()
endif()

if(NOT ESP_PLATFORM)
    if(NOT SKIP_MBEDTLS_FOR_OPENSSL_EMULATION)
        add_library(mbedtls STATIC ${MBEDTLS_SOURCES})
        target_include_directories(mbedtls SYSTEM PUBLIC ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/include)
    endif()
    if(ENABLE_LIBCVC)
        add_library(libcvc STATIC ${LIBCVC_SOURCES})
        target_include_directories(libcvc SYSTEM PUBLIC ${CMAKE_CURRENT_LIST_DIR}/third-party/libcvc/src ${CMAKE_CURRENT_LIST_DIR}/third-party/libcvc/include)
        target_link_libraries(libcvc PRIVATE mbedtls)
        list(APPEND LIBRARIES libcvc)
    endif()
    if(USB_ITF_HID)
        add_library(tinycbor STATIC ${CBOR_SOURCES})
        target_include_directories(tinycbor SYSTEM PUBLIC ${CMAKE_CURRENT_LIST_DIR}/third-party/tinycbor/src)
        list(APPEND LIBRARIES tinycbor)
    endif()
    if(USB_ITF_LWIP)
        add_library(cjson STATIC ${CJSON_SOURCES})
        target_include_directories(cjson SYSTEM PUBLIC ${CMAKE_CURRENT_LIST_DIR}/third-party/cjson)
        list(APPEND LIBRARIES cjson)
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
    if(USB_ITF_LWIP)
        list(APPEND LIBRARIES
            pico_lwip
            pico_lwip_nosys
        )
    endif()
endif()

if(ENABLE_PQC)
    list(APPEND LIBRARIES
        mlkem768
        mlkem1024
        mlkem512
        mldsa44
        mldsa65
        mldsa87
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

if(USB_ITF_HID)
    list(APPEND PICOKEYS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/hid/hid.c
    )
    list(APPEND INCLUDES
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/hid
    )
endif()

if(USB_ITF_CCID)
    list(APPEND PICOKEYS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/ccid/ccid.c
    )
    list(APPEND INCLUDES
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/ccid
    )
endif()

if(NOT MSVC)
    add_compile_options("-fmacro-prefix-map=${CMAKE_CURRENT_LIST_DIR}/=")
else()
    list(APPEND PICOKEYS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/mman.c
    )
endif()
if(ENABLE_EMULATION)
    if(APPLE)
        add_definitions("-Wno-deprecated-declarations")
        target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE
                "-framework IOKit"
                "-framework CoreFoundation"
        )
    elseif(MSVC)
        target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE Ncrypt)
    elseif(UNIX AND NOT APPLE AND TSS2_ESYS_LIB AND TSS2_TCTILDR_LIB)
        target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ${TSS2_ESYS_LIB} ${TSS2_TCTILDR_LIB})
    endif()
    add_compile_definitions(ENABLE_EMULATION)
    list(APPEND PICOKEYS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/emulation/emulation.c
    )
    if(USE_OPENSSL_EMULATION_WRAPPER)
        list(APPEND PICOKEYS_SOURCES
            ${CMAKE_CURRENT_LIST_DIR}/src/usb/emulation/openssl.c
        )
    endif()
    list(APPEND MBEDTLS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/aesni.c
    )
    list(APPEND INCLUDES
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/emulation
    )
else()
    list(APPEND PICOKEYS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/usb_descriptors.c
    )
endif()

if(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -wd5045 -wd4820 -wd5105")

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

if(USB_ITF_LWIP)
    list(APPEND PICOKEYS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/lwip/rest.c
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/lwip/rest_server.c
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/lwip/rest_server_tls.c
    )
    list(APPEND INCLUDES
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/lwip
    )
    if(NOT ENABLE_EMULATION)
        list(APPEND PICOKEYS_SOURCES
            ${CMAKE_CURRENT_LIST_DIR}/src/usb/lwip/lwip.c
        )
        if ((NOT ESP_PLATFORM) AND (NOT IDF_TARGET))
            list(APPEND PICOKEYS_SOURCES
                ${PICO_TINYUSB_PATH}/lib/networking/dhserver.c
                ${PICO_TINYUSB_PATH}/lib/networking/dnserver.c
            )
            list(APPEND INCLUDES
                ${PICO_TINYUSB_PATH}/lib/networking
                ${PICO_LWIP_PATH}/src/include/lwip/apps
            )
            message(STATUS "TINYUSB_PATH:\t\t ${PICO_TINYUSB_PATH}")
            message(STATUS "LWIP_PATH:\t\t ${PICO_LWIP_PATH}")
        endif()
    endif()
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
    list(APPEND PICOKEYS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/config/rp2350/alt/sha256_alt.c
    )
    add_compile_definitions(MBEDTLS_SHA256_ALT=1)
    list(APPEND LIBRARIES pico_sha256)
endif()
set(INTERNAL_SOURCES ${PICOKEYS_SOURCES})

if(NOT TARGET picokeys_sdk)
    if(PICO_PLATFORM)
        pico_add_library(picokeys_sdk)

        target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ${LIBRARIES})
    else()
        add_impl_library(picokeys_sdk)
    endif()
    target_sources(picokeys_sdk INTERFACE ${PICOKEYS_SOURCES})
    target_include_directories(picokeys_sdk INTERFACE ${INCLUDES})
    target_include_directories(picokeys_sdk SYSTEM INTERFACE ${SYSTEM_INCLUDES})
    target_link_libraries(picokeys_sdk INTERFACE ${LIBRARIES})
endif()
