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

cmake_minimum_required(VERSION 3.13)

project(pico_hsm_sdk C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

if(ENABLE_EMULATION)
else()
include(pico_sdk_import.cmake)
pico_sdk_init()
endif()

add_executable(pico_hsm_sdk_exe)

set(USB_ITF_HID 1)
set(USB_ITF_CCID 1)

include(pico_hsm_sdk_import.cmake)

target_compile_options(pico_hsm_sdk_exe PUBLIC
    -Wall
    -Werror
)

if(ENABLE_EMULATION)
else()
pico_add_extra_outputs(pico_hsm_sdk_exe)
target_link_libraries(pico_hsm_sdk_exe PRIVATE pico_hsm_sdk pico_stdlib pico_multicore hardware_flash hardware_sync hardware_adc pico_unique_id hardware_rtc tinyusb_device tinyusb_board)

endif()
