include_guard(GLOBAL)

function(picokeys_trusted_region_enabled out_var)
    if(PICO_RP2350)
        set(${out_var} TRUE PARENT_SCOPE)
    else()
        set(${out_var} FALSE PARENT_SCOPE)
    endif()
endfunction()

macro(picokeys_init_trusted_config)
    set(PICOKEYS_TRUSTED_REGION_FLASH_BASE "0x100B0000" CACHE STRING "Fixed flash base for the trusted measurement region on Pico firmware builds")
    set(PICOKEYS_TRUSTED_STATE_RAM_BASE "0x20070000" CACHE STRING "Fixed RAM base for trusted writable state on Pico firmware builds")

    set(TRUSTED_MBEDTLS_HELPER_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/trusted/trusted_mem.c
    )
endmacro()

macro(picokeys_resolve_trusted_toolchain)
    if(CMAKE_C_COMPILER AND PICO_RP2350)
        set(PICOKEYS_LIBGCC_QUERY_ARGS -print-libgcc-file-name)
        set(PICOKEYS_LIBGCC_QUERY_ARGS
            -mthumb
            -march=armv8-m.main+fp
            -mfloat-abi=softfp
            -print-libgcc-file-name
        )
        execute_process(
            COMMAND ${CMAKE_C_COMPILER} ${PICOKEYS_LIBGCC_QUERY_ARGS}
            OUTPUT_VARIABLE PICOKEYS_LIBGCC
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
    endif()
endmacro()

function(configure_picokeys_mbedtls_target target_name)
    picokeys_trusted_region_enabled(enable_trusted_region)
    if(enable_trusted_region)
        target_sources(${target_name} PRIVATE ${TRUSTED_MBEDTLS_HELPER_SOURCES})
        target_compile_definitions(${target_name} PRIVATE
            MBEDTLS_PLATFORM_ZEROIZE_ALT
            memset=picokeys_trusted_memset
            memcpy=picokeys_trusted_memcpy
            memmove=picokeys_trusted_memmove
            memcmp=picokeys_trusted_memcmp
        )
        target_compile_options(${target_name} PRIVATE -fno-builtin)
    endif()
endfunction()

function(configure_picokeys_trusted_mbedtls_target target_name)
    target_sources(${target_name} PRIVATE ${TRUSTED_MBEDTLS_HELPER_SOURCES})
    target_compile_definitions(${target_name} PRIVATE
        MBEDTLS_PLATFORM_ZEROIZE_ALT
        memset=picokeys_trusted_memset
        memcpy=picokeys_trusted_memcpy
        memmove=picokeys_trusted_memmove
        memcmp=picokeys_trusted_memcmp
        strlen=picokeys_trusted_strlen
        strncmp=picokeys_trusted_strncmp
        strncpy=picokeys_trusted_strncpy
        strchr=picokeys_trusted_strchr
        calloc=picokeys_trusted_calloc
        free=picokeys_trusted_free
        at_the_end_of_time=picokeys_trusted_at_the_end_of_time
        pico_sha256_lock=picokeys_trusted_pico_sha256_lock
        pico_sha256_unlock=picokeys_trusted_pico_sha256_unlock
        pico_sha256_cleanup=picokeys_trusted_pico_sha256_cleanup
        pico_sha256_try_start=picokeys_trusted_pico_sha256_try_start
        pico_sha256_start_blocking_until=picokeys_trusted_pico_sha256_start_blocking_until
        pico_sha256_update=picokeys_trusted_pico_sha256_update
        pico_sha256_update_blocking=picokeys_trusted_pico_sha256_update_blocking
        pico_sha256_finish=picokeys_trusted_pico_sha256_finish
    )
    target_compile_options(${target_name} PRIVATE
        -fno-builtin
        -ffunction-sections
        -fdata-sections
    )
    if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${target_name} PRIVATE
            -fno-tree-loop-distribute-patterns
        )
    endif()
endfunction()

macro(picokeys_setup_trusted_mbedtls)
    if(NOT SKIP_MBEDTLS_FOR_OPENSSL_EMULATION AND PICO_PLATFORM AND PICO_RP2350 AND NOT ENABLE_EMULATION)
        add_library(trusted_mbedtls_build STATIC ${MBEDTLS_SOURCES})
        target_include_directories(trusted_mbedtls_build SYSTEM PUBLIC
            ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/include
            ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library
        )
        configure_picokeys_trusted_mbedtls_target(trusted_mbedtls_build)
        set(TRUSTED_MBEDTLS_ARCHIVE ${CMAKE_CURRENT_BINARY_DIR}/libtrusted_mbedtls.a)
        set(TRUSTED_LIBGCC_DIR ${CMAKE_CURRENT_BINARY_DIR}/trusted_libgcc)
        add_custom_command(
            OUTPUT ${TRUSTED_MBEDTLS_ARCHIVE}
            COMMAND ${CMAKE_COMMAND} -E rm -f ${TRUSTED_MBEDTLS_ARCHIVE}
            COMMAND ${CMAKE_COMMAND} -E rm -rf ${TRUSTED_LIBGCC_DIR}
            COMMAND ${CMAKE_COMMAND} -E make_directory ${TRUSTED_LIBGCC_DIR}
            COMMAND ${CMAKE_OBJCOPY}
                --prefix-alloc-sections=.trusted
                --redefine-sym memset=picokeys_trusted_memset
                --redefine-sym mbedtls_sha256_init=picokeys_trusted_sha256_init
                --redefine-sym mbedtls_sha256_free=picokeys_trusted_sha256_free
                --redefine-sym mbedtls_sha256_starts=picokeys_trusted_sha256_starts
                --redefine-sym mbedtls_sha256_update=picokeys_trusted_sha256_update
                --redefine-sym mbedtls_sha256_finish=picokeys_trusted_sha256_finish
                --redefine-sym mbedtls_sha256_clone=picokeys_trusted_sha256_clone
                --redefine-sym __aeabi_uldivmod=picokeys_trusted___aeabi_uldivmod
                $<TARGET_FILE:trusted_mbedtls_build>
                ${TRUSTED_MBEDTLS_ARCHIVE}
            COMMAND ${CMAKE_COMMAND} -E chdir ${TRUSTED_LIBGCC_DIR}
                ${CMAKE_AR} x ${PICOKEYS_LIBGCC}
                _aeabi_uldivmod.o
                _udivmoddi4.o
                _dvmd_tls.o
            COMMAND ${CMAKE_OBJCOPY}
                --prefix-alloc-sections=.trusted
                --redefine-sym __aeabi_uldivmod=picokeys_trusted___aeabi_uldivmod
                --redefine-sym __udivmoddi4=picokeys_trusted___udivmoddi4
                --redefine-sym __aeabi_idiv0=picokeys_trusted___aeabi_idiv0
                ${TRUSTED_LIBGCC_DIR}/_aeabi_uldivmod.o
                ${TRUSTED_LIBGCC_DIR}/_aeabi_uldivmod.trusted.o
            COMMAND ${CMAKE_OBJCOPY}
                --prefix-alloc-sections=.trusted
                --redefine-sym __udivmoddi4=picokeys_trusted___udivmoddi4
                ${TRUSTED_LIBGCC_DIR}/_udivmoddi4.o
                ${TRUSTED_LIBGCC_DIR}/_udivmoddi4.trusted.o
            COMMAND ${CMAKE_OBJCOPY}
                --prefix-alloc-sections=.trusted
                --redefine-sym __aeabi_idiv0=picokeys_trusted___aeabi_idiv0
                ${TRUSTED_LIBGCC_DIR}/_dvmd_tls.o
                ${TRUSTED_LIBGCC_DIR}/_dvmd_tls.trusted.o
            COMMAND ${CMAKE_AR} q ${TRUSTED_MBEDTLS_ARCHIVE}
                ${TRUSTED_LIBGCC_DIR}/_aeabi_uldivmod.trusted.o
                ${TRUSTED_LIBGCC_DIR}/_udivmoddi4.trusted.o
                ${TRUSTED_LIBGCC_DIR}/_dvmd_tls.trusted.o
            COMMAND ${CMAKE_RANLIB} ${TRUSTED_MBEDTLS_ARCHIVE}
            DEPENDS trusted_mbedtls_build
            VERBATIM
        )
        add_custom_target(trusted_mbedtls_archive DEPENDS ${TRUSTED_MBEDTLS_ARCHIVE})
        add_library(trusted_mbedtls STATIC IMPORTED GLOBAL)
        add_dependencies(trusted_mbedtls trusted_mbedtls_archive)
        set_target_properties(trusted_mbedtls PROPERTIES
            IMPORTED_LOCATION ${TRUSTED_MBEDTLS_ARCHIVE}
        )
    endif()
endmacro()

macro(picokeys_configure_trusted_support_sources)
    picokeys_trusted_region_enabled(enable_trusted_region)
    if(enable_trusted_region)
        if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
            set_source_files_properties(${CMAKE_CURRENT_LIST_DIR}/src/trusted/trusted_mem.c PROPERTIES
                COMPILE_OPTIONS "-fno-builtin;-fno-tree-loop-distribute-patterns"
            )
        else()
            set_source_files_properties(${CMAKE_CURRENT_LIST_DIR}/src/trusted/trusted_mem.c PROPERTIES
                COMPILE_OPTIONS "-fno-builtin"
            )
        endif()
    endif()
    if(DEFINED TRUSTED_REGION_EMBED_SOURCE)
        set_source_files_properties(${TRUSTED_REGION_EMBED_SOURCE} PROPERTIES
            OBJECT_DEPENDS "${TRUSTED_REGION_EMBED_INPUT}"
        )
        list(APPEND PICOKEYS_SOURCES
            ${TRUSTED_REGION_EMBED_SOURCE}
        )
    endif()
endmacro()

macro(picokeys_configure_rp2350_trusted)
    if(TARGET trusted_mbedtls_build)
        target_include_directories(trusted_mbedtls_build PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/config/rp2350/alt
        )
        target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC
            ${CMAKE_CURRENT_LIST_DIR}/src/trusted
        )
        target_sources(trusted_mbedtls_build PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/config/rp2350/alt/sha256_alt.c
            ${CMAKE_CURRENT_LIST_DIR}/src/trusted/trusted_pico_sha256.c
        )
        target_link_libraries(trusted_mbedtls_build PRIVATE
            pico_sha256_headers
            pico_bootrom_headers
            pico_time_headers
        )
    endif()
endmacro()

macro(picokeys_link_trusted_region target_name)
    if(TARGET trusted_mbedtls)
        target_link_options(${target_name} PRIVATE
            "LINKER:--defsym=__trusted_region_fixed_base=${PICOKEYS_TRUSTED_REGION_FLASH_BASE}"
            "LINKER:-T,${CMAKE_CURRENT_LIST_DIR}/config/rp2350/ld/trusted_region.ld"
            "LINKER:-T,${CMAKE_CURRENT_LIST_DIR}/config/rp2350/ld/trusted_state.ld"
        )
        set_property(TARGET ${target_name} APPEND PROPERTY LINK_DEPENDS
            ${CMAKE_CURRENT_LIST_DIR}/config/rp2350/ld/trusted_region.ld
            ${CMAKE_CURRENT_LIST_DIR}/config/rp2350/ld/trusted_state.ld
        )
    endif()
endmacro()
