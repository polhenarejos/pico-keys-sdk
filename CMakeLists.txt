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
else()
    if(NOT ENABLE_EMULATION)
        set(PICO_USE_FASTEST_SUPPORTED_CLOCK 1)
        include(pico_sdk_import.cmake)
    endif()

    project(pico_rescue C CXX ASM)

    set(CMAKE_C_STANDARD 11)
    set(CMAKE_CXX_STANDARD 17)

    if(NOT DEFINED __FOR_CI)
        set(__FOR_CI 0)
    endif()
    if(__FOR_CI)
        add_definitions(-D__FOR_CI)
    endif()

    add_executable(pico_rescue)
endif()

set(USB_ITF_CCID 1)
set(USB_ITF_WCID 1)
include(cmake/version.cmake)
include(pico_keys_sdk_import.cmake)
if(NOT ESP_PLATFORM)
    set(SOURCES ${PICO_KEYS_SOURCES})
endif()
set(SOURCES ${SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/src/fs/files.c
    ${CMAKE_CURRENT_LIST_DIR}/src/version.c
)

SET_VERSION(ver_major ver_minor "${CMAKE_CURRENT_LIST_DIR}/src/pico_keys_version.h" 3)

if(ESP_PLATFORM)
    project(pico_rescue)
endif()

if(NOT ESP_PLATFORM)
    target_sources(pico_rescue PUBLIC ${SOURCES})
    target_include_directories(pico_rescue PUBLIC ${INCLUDES})

    target_compile_options(pico_rescue PUBLIC
        -Wall
    )
    if(NOT MSVC)
        target_compile_options(pico_rescue PUBLIC
            -Werror
        )
    endif()

    if(ENABLE_EMULATION)
        if(NOT MSVC)
            target_compile_options(pico_rescue PUBLIC
                -fdata-sections
                -ffunction-sections
            )
        endif()
        if(APPLE)
            target_link_options(pico_rescue PUBLIC
                -Wl,-dead_strip
            )
        elseif(MSVC)
            target_compile_options(pico_rescue PUBLIC
                -WX
            )

            target_link_libraries(pico_rescue PUBLIC wsock32 ws2_32 Bcrypt)
        else()
            target_link_options(pico_rescue PUBLIC
                -Wl,--gc-sections
            )
        endif(APPLE)
        target_link_libraries(pico_rescue PRIVATE pthread m)
    else()
        pico_add_extra_outputs(${CMAKE_PROJECT_NAME})
    endif()
endif()

