 # 
 # This file is part of the Pico CCID distribution (https://github.com/polhenarejos/pico-ccid).
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

cmake_minimum_required(VERSION 3.13)

include(pico_sdk_import.cmake)

project(pico_ccid C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

add_executable(pico_ccid)

if (NOT DEFINED USB_VID)
    set(USB_VID 0xFEFF)
endif()
add_definitions(-DUSB_VID=${USB_VID})
if (NOT DEFINED USB_PID)
    set(USB_PID 0xFCFD)
endif()
add_definitions(-DUSB_PID=${USB_PID})
configure_file(${CMAKE_CURRENT_LIST_DIR}/config/mbedtls_config.h ${CMAKE_CURRENT_LIST_DIR}/mbedtls/include/mbedtls COPYONLY)

target_sources(pico_ccid PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/usb.c
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/usb_descriptors.c
        ${CMAKE_CURRENT_LIST_DIR}/src/ccid/ccid2040.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/file.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/flash.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/low_flash.c
        ${CMAKE_CURRENT_LIST_DIR}/src/rng/random.c
        ${CMAKE_CURRENT_LIST_DIR}/src/rng/neug.c
        ${CMAKE_CURRENT_LIST_DIR}/src/ccid/eac.c
        ${CMAKE_CURRENT_LIST_DIR}/src/ccid/crypto_utils.c
        ${CMAKE_CURRENT_LIST_DIR}/src/ccid/asn1.c
        )

target_include_directories(pico_ccid PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/src/fs
        ${CMAKE_CURRENT_LIST_DIR}/src/ccid
        ${CMAKE_CURRENT_LIST_DIR}/src/rng
        ${CMAKE_CURRENT_LIST_DIR}/src/usb
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/include
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library
        )

target_compile_options(pico_ccid PUBLIC
    -Wall
    -Werror
)
    
pico_add_extra_outputs(pico_ccid)

target_link_libraries(pico_ccid PRIVATE pico_stdlib pico_multicore hardware_flash hardware_sync hardware_adc pico_unique_id hardware_rtc tinyusb_device tinyusb_board)
