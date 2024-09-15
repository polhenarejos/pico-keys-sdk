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

 cmake_minimum_required(VERSION 3.16)

if(ESP_PLATFORM)
set(EXTRA_COMPONENT_DIRS src)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
set(USB_ITF_CCID 1)
#set(USB_ITF_HID 1)
include(pico_keys_sdk_import.cmake)
project(pico_keys_sdk)
else()

 if(ENABLE_EMULATION)
 else()
 include(pico_sdk_import.cmake)
 endif()

 project(pico_keys C CXX ASM)

 set(CMAKE_C_STANDARD 11)
 set(CMAKE_CXX_STANDARD 17)

 if(ENABLE_EMULATION)
  else()
 pico_sdk_init()
 endif()

 if (NOT DEFINED __FOR_CI)
     set(__FOR_CI 0)
 endif()
 if (__FOR_CI)
     add_definitions(-D__FOR_CI)
 endif()

set(USB_ITF_CCID 1)
set(USB_ITF_HID 1)
include(pico_keys_sdk_import.cmake)

add_executable(pico_keys_sdk_exe)

target_compile_options(pico_keys_sdk_exe PUBLIC
    -Wall
    -Werror
)

if(ENABLE_EMULATION)
target_compile_options(pico_keys_sdk_exe PUBLIC
        -fdata-sections
        -ffunction-sections
        )
if(APPLE)
target_link_options(pico_keys_sdk_exe PUBLIC
        -Wl,-dead_strip
        )
else()
target_link_options(pico_keys_sdk_exe PUBLIC
        -Wl,--gc-sections
        )
endif (APPLE)
else()
pico_add_extra_outputs(pico_keys_sdk_exe)

target_link_libraries(pico_keys_sdk_exe PRIVATE pico_keys_sdk pico_stdlib pico_multicore hardware_flash hardware_sync hardware_adc pico_unique_id hardware_rtc tinyusb_device tinyusb_board)
endif()

endif()
