 #
 # This file is part of the Pico HSM SDK distribution (https://github.com/polhenarejos/pico-hsm-sdk).
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

if (NOT DEFINED USB_VID)
    set(USB_VID 0xFEFF)
endif()
add_definitions(-DUSB_VID=${USB_VID})
if (NOT DEFINED USB_PID)
    set(USB_PID 0xFCFD)
endif()
add_definitions(-DUSB_PID=${USB_PID})
if (NOT DEFINED DEBUG_APDU)
    set(DEBUG_APDU 0)
endif()
if (NOT DEFINED ENABLE_EMULATION)
    set(ENABLE_EMULATION 0)
endif()

option(ENABLE_DELAYED_BOOT "Enable/disable delayed boot" OFF)
if(ENABLE_DELAYED_BOOT)
    add_definitions(-DPICO_XOSC_STARTUP_DELAY_MULTIPLIER=64)
    message(STATUS "Delayed boot:\t\t enabled")
else()
message(STATUS "Delayed boot:\t\t disabled")
endif(ENABLE_DELAYED_BOOT)
if(USB_ITF_HID)
    add_definitions(-DUSB_ITF_HID=1)
    message(STATUS "USB HID Interface:\t\t enabled")
endif(USB_ITF_HID)
if(USB_ITF_CCID)
    add_definitions(-DUSB_ITF_CCID=1)
    message(STATUS "USB CCID Interface:\t\t enabled")
endif(USB_ITF_CCID)
add_definitions(-DDEBUG_APDU=${DEBUG_APDU})
add_definitions(-DMBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_LIST_DIR}/config/mbedtls_config.h")

message(STATUS "USB VID/PID: ${USB_VID}:${USB_PID}")

set(SOURCES ${SOURCES}
${CMAKE_CURRENT_LIST_DIR}/src/main.c
${CMAKE_CURRENT_LIST_DIR}/src/usb/usb.c
${CMAKE_CURRENT_LIST_DIR}/src/fs/file.c
${CMAKE_CURRENT_LIST_DIR}/src/fs/flash.c
${CMAKE_CURRENT_LIST_DIR}/src/fs/low_flash.c
${CMAKE_CURRENT_LIST_DIR}/src/rng/random.c
${CMAKE_CURRENT_LIST_DIR}/src/rng/hwrng.c
${CMAKE_CURRENT_LIST_DIR}/src/eac.c
${CMAKE_CURRENT_LIST_DIR}/src/crypto_utils.c
${CMAKE_CURRENT_LIST_DIR}/src/asn1.c
${CMAKE_CURRENT_LIST_DIR}/src/apdu.c

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
${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/hash_info.c
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
)
set(INCLUDES ${INCLUDES}
${CMAKE_CURRENT_LIST_DIR}/src
${CMAKE_CURRENT_LIST_DIR}/src/usb
${CMAKE_CURRENT_LIST_DIR}/src/fs
${CMAKE_CURRENT_LIST_DIR}/src/rng
${CMAKE_CURRENT_LIST_DIR}/mbedtls/include
${CMAKE_CURRENT_LIST_DIR}/mbedtls/library
)

if(USB_ITF_HID OR ENABLE_EMULATION)
set(SOURCES ${SOURCES}
${CMAKE_CURRENT_LIST_DIR}/tinycbor/src/cborencoder.c
${CMAKE_CURRENT_LIST_DIR}/tinycbor/src/cborparser.c
${CMAKE_CURRENT_LIST_DIR}/tinycbor/src/cborparser_dup_string.c
${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/x509write_crt.c
${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/x509_create.c
${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/x509write_csr.c
${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/pk.c
${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/pk_wrap.c
${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/pkwrite.c
)

set(INCLUDES ${INCLUDES}
${CMAKE_CURRENT_LIST_DIR}/tinycbor/src
)
endif()

function(add_impl_library target)
    add_library(${target} INTERFACE)
    string(TOUPPER ${target} TARGET_UPPER)
    target_compile_definitions(${target} INTERFACE LIB_${TARGET_UPPER}=1)
endfunction()
if(${USB_ITF_HID})
    set(SOURCES ${SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/src/usb/hid/hid.c
    )
    set(INCLUDES ${INCLUDES}
    ${CMAKE_CURRENT_LIST_DIR}/src/usb/hid
    )
endif()
if (ENABLE_EMULATION)
    if(APPLE)
        set(CMAKE_OSX_SYSROOT "/Library/Developer/CommandLineTools//SDKs/MacOSX11.3.sdk")
    endif()
    add_definitions(-DENABLE_EMULATION)
    set(SOURCES ${SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/src/usb/emulation/emulation.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ctr_drbg.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/entropy.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/entropy_poll.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/aesni.c
    )
    set(INCLUDES ${INCLUDES}
    ${CMAKE_CURRENT_LIST_DIR}/src/usb/emulation
    )
    if (NOT TARGET pico_hsm_sdk)
        add_impl_library(pico_hsm_sdk)
        target_sources(pico_hsm_sdk INTERFACE
        ${SOURCES}
        )
        target_include_directories(pico_hsm_sdk INTERFACE
        ${INCLUDES}
        )
    endif()
else()

    if (${USB_ITF_CCID})
        set(SOURCES ${SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/ccid/ccid.c
        )
        set(INCLUDES ${INCLUDES}
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/ccid
        )
    endif()

    set(SOURCES ${SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/src/usb/usb_descriptors.c
    )
    if (NOT TARGET pico_hsm_sdk)
        pico_add_library(pico_hsm_sdk)

        target_sources(pico_hsm_sdk INTERFACE
                ${SOURCES}
                )

        target_include_directories(pico_hsm_sdk INTERFACE
                ${INCLUDES}
                )

        target_link_libraries(pico_hsm_sdk INTERFACE pico_stdlib pico_multicore hardware_flash hardware_sync hardware_adc pico_unique_id hardware_rtc tinyusb_device tinyusb_board hardware_pio)
    endif()
endif()



