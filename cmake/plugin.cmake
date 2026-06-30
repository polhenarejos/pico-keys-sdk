set(PICOKEYS_PLUGIN_SDK_ROOT "${CMAKE_CURRENT_LIST_DIR}/..")

function(picokeys_add_plugin TARGET)
    set(oneValueArgs SOURCE LINKER OUTPUT_UF2)
    cmake_parse_arguments(PK_PLUGIN "" "${oneValueArgs}" "" ${ARGN})

    if(NOT PK_PLUGIN_SOURCE)
        message(FATAL_ERROR "picokeys_add_plugin(${TARGET}) requires SOURCE")
    endif()
    if(NOT PK_PLUGIN_OUTPUT_UF2)
        set(PK_PLUGIN_OUTPUT_UF2 "${TARGET}.uf2")
    endif()

    if(ENABLE_EMULATION)
        add_library(${TARGET} MODULE ${PK_PLUGIN_SOURCE})
        set_target_properties(${TARGET} PROPERTIES
            PREFIX ""
            WINDOWS_EXPORT_ALL_SYMBOLS ON
        )
        if(NOT MSVC)
            target_compile_options(${TARGET} PRIVATE
                -fvisibility=default
            )
        endif()
        target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE
            PICOKEYS_EMULATION_PLUGIN_PATH="$<TARGET_FILE:${TARGET}>"
        )
    else()
        if(NOT PK_PLUGIN_LINKER)
            message(FATAL_ERROR "picokeys_add_plugin(${TARGET}) requires LINKER for non-emulation builds")
        endif()

        add_executable(${TARGET}
            ${PK_PLUGIN_SOURCE}
        )

        target_link_options(${TARGET} PRIVATE
            "LINKER:--defsym=__picokeys_plugin_flash_base=${PICOKEYS_PLUGIN_FLASH_BASE}"
            "LINKER:--defsym=__picokeys_plugin_flash_size=${PICOKEYS_PLUGIN_FLASH_SIZE}"
            "LINKER:-T,${PK_PLUGIN_LINKER}"
            "LINKER:-n"
            "LINKER:--gc-sections"
            "LINKER:--build-id=none"
            -nostartfiles
            -nostdlib
            -nodefaultlibs
        )

        pico_set_uf2_family(${TARGET} 0xe48bff57)
        pico_add_extra_outputs(${TARGET})

        if(NOT PK_PLUGIN_OUTPUT_UF2 STREQUAL "${TARGET}.uf2")
            add_custom_command(TARGET ${TARGET} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy
                    $<TARGET_FILE_DIR:${TARGET}>/${TARGET}.uf2
                    $<TARGET_FILE_DIR:${TARGET}>/${PK_PLUGIN_OUTPUT_UF2}
            )
        endif()
    endif()

    target_include_directories(${TARGET} PRIVATE
        ${PICOKEYS_PLUGIN_SDK_ROOT}/src/plugin
    )

    target_compile_options(${TARGET} PRIVATE
        -Os
        -ffunction-sections
        -fdata-sections
    )

    target_compile_definitions(${TARGET} PRIVATE
        PICOKEYS_PLUGIN_FLASH_BASE=${PICOKEYS_PLUGIN_FLASH_BASE}
        PICOKEYS_PLUGIN_FLASH_SIZE=${PICOKEYS_PLUGIN_FLASH_SIZE}
    )
endfunction()

function(picokeys_add_flash_plugin TARGET)
    picokeys_add_plugin(${TARGET} ${ARGN})
endfunction()
