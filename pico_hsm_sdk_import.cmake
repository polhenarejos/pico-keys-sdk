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
if (NOT DEFINED HSM_DRIVER)
    set(HSM_DRIVER "ccid")
endif()
add_definitions(-DDEBUG_APDU=${DEBUG_APDU})
configure_file(${CMAKE_CURRENT_LIST_DIR}/config/mbedtls_config.h ${CMAKE_CURRENT_LIST_DIR}/mbedtls/include/mbedtls COPYONLY)

message(STATUS "HSM driver: ${HSM_DRIVER}")
message(STATUS "USB VID/PID: ${USB_VID}:${USB_PID}")

configure_file(${CMAKE_CURRENT_LIST_DIR}/config/mbedtls_config.h ${CMAKE_CURRENT_LIST_DIR}/mbedtls/include/mbedtls COPYONLY)

if (NOT TARGET pico_hsm_sdk)
    pico_add_impl_library(pico_hsm_sdk)

    target_sources(pico_hsm_sdk INTERFACE
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
            ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/cmac.c
            ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/cipher.c
            ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/cipher_wrap.c
            ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/constant_time.c
            ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ecdsa.c
            ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ecdh.c
            ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ecp.c
            ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ecp_curves.c
            ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/hkdf.c
            ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/md.c
            ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/md5.c
            ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/oid.c
            ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/platform_util.c
            ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ripemd160.c
            ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/rsa.c
            ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/rsa_alt_helpers.c
            ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/sha1.c
            ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/sha256.c
            ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/sha512.c
            ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/x509write_crt.c
            )

    if (${HSM_DRIVER} STREQUAL "ccid")
        target_sources(pico_hsm_sdk INTERFACE
                ${CMAKE_CURRENT_LIST_DIR}/src/usb/ccid/usb_descriptors.c
                ${CMAKE_CURRENT_LIST_DIR}/src/usb/ccid/ccid.c
                )

        target_include_directories(pico_hsm_sdk INTERFACE
                ${CMAKE_CURRENT_LIST_DIR}/src/usb/ccid
                )
    elseif (${HSM_DRIVER} STREQUAL "hid")
        target_sources(pico_hsm_sdk INTERFACE
                ${CMAKE_CURRENT_LIST_DIR}/src/usb/hid/hid.c
                ${CMAKE_CURRENT_LIST_DIR}/src/usb/hid/usb_descriptors.c
                )
        target_include_directories(pico_hsm_sdk INTERFACE
                ${CMAKE_CURRENT_LIST_DIR}/src/usb/hid
                )
    endif()

    target_include_directories(pico_hsm_sdk INTERFACE
            ${CMAKE_CURRENT_LIST_DIR}/src
            ${CMAKE_CURRENT_LIST_DIR}/src/usb
            ${CMAKE_CURRENT_LIST_DIR}/src/fs
            ${CMAKE_CURRENT_LIST_DIR}/src/rng
            ${CMAKE_CURRENT_LIST_DIR}/mbedtls/include
            ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library
            )

    target_link_libraries(pico_hsm_sdk INTERFACE pico_stdlib pico_multicore hardware_flash hardware_sync hardware_adc pico_unique_id hardware_rtc tinyusb_device tinyusb_board)
endif()




