#
# Pico Keys SDK build helper functions
#

function(picokeys_apply_strict_flags)
    set(options)
    set(oneValueArgs FILTER_REGEX)
    set(multiValueArgs SOURCES)
    cmake_parse_arguments(PKAS "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT PKAS_SOURCES)
        return()
    endif()

    if (MSVC)
        set(PICOKEYS_STRICT_FLAGS
            -Wall
            -Zc:strictStrings
            -WX
        )
    else ()
        set(PICOKEYS_STRICT_FLAGS
            -pipe
            -funsigned-char
            -fstrict-aliasing
            -fdiagnostics-color=auto
            -Wextra
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
            -Wmissing-prototypes
            -Wstrict-prototypes
            -Wold-style-definition
            -Wbad-function-cast
            -Wnested-externs
            -Wmissing-declarations
            -Werror
        )
    endif()

    foreach(src IN LISTS PKAS_SOURCES)
        if(PKAS_FILTER_REGEX)
            if(NOT src MATCHES "${PKAS_FILTER_REGEX}")
                continue()
            endif()
        endif()
        set_property(SOURCE "${src}" APPEND PROPERTY COMPILE_OPTIONS ${PICOKEYS_STRICT_FLAGS})
    endforeach()
endfunction()

function(picokeys_configure_host_target)
    set(options)
    set(oneValueArgs TARGET STRICT_FILTER_REGEX MACOS_APP_BUNDLE_ID MACOS_APP_DEVELOPMENT_TEAM)
    set(multiValueArgs SOURCES INCLUDES)
    cmake_parse_arguments(PKCHT "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT PKCHT_TARGET OR ESP_PLATFORM)
        return()
    endif()

    target_sources(${PKCHT_TARGET} PUBLIC ${PKCHT_SOURCES})
    target_include_directories(${PKCHT_TARGET} PUBLIC ${PKCHT_INCLUDES})
    target_compile_options(${PKCHT_TARGET} PRIVATE -Wall)

    picokeys_apply_strict_flags(
        SOURCES ${PKCHT_SOURCES}
        FILTER_REGEX "${PKCHT_STRICT_FILTER_REGEX}"
    )

    if(NOT MSVC)
        target_compile_options(${PKCHT_TARGET} PRIVATE -Werror)

        string(FIND ${CMAKE_C_COMPILER} ":" COMPILER_COLON)
        if(${COMPILER_COLON} GREATER_EQUAL 0)
            target_compile_options(${PKCHT_TARGET} PRIVATE -Wno-error=use-after-free)
        endif()
    endif()

    if(ENABLE_EMULATION)
        if(NOT MSVC)
            target_compile_options(${PKCHT_TARGET} PRIVATE -fdata-sections -ffunction-sections)
        endif()

        if(APPLE)
            target_link_options(${PKCHT_TARGET} PRIVATE -Wl,-dead_strip)

            if(MACOS_APP)
                target_link_libraries(${PKCHT_TARGET} PRIVATE
                    "-framework Security"
                    "-framework CoreFoundation"
                )
                if(CMAKE_GENERATOR STREQUAL "Xcode")
                    if("${PKCHT_MACOS_APP_DEVELOPMENT_TEAM}" STREQUAL "")
                        message(FATAL_ERROR "MACOS_APP=1 with Xcode requires MACOS_APP_DEVELOPMENT_TEAM")
                    endif()
                    target_compile_options(${PKCHT_TARGET} PRIVATE -Wno-missing-include-dirs)
                    set_target_properties(${PKCHT_TARGET} PROPERTIES
                        MACOSX_BUNDLE TRUE
                        MACOSX_BUNDLE_GUI_IDENTIFIER "${PKCHT_MACOS_APP_BUNDLE_ID}"
                        MACOSX_BUNDLE_BUNDLE_NAME "${PKCHT_TARGET}"
                        XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER "${PKCHT_MACOS_APP_BUNDLE_ID}"
                        XCODE_ATTRIBUTE_CODE_SIGN_STYLE "Automatic"
                        XCODE_ATTRIBUTE_DEVELOPMENT_TEAM "${PKCHT_MACOS_APP_DEVELOPMENT_TEAM}"
                        XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "Apple Development"
                        XCODE_ATTRIBUTE_CODE_SIGN_ENTITLEMENTS "${CMAKE_CURRENT_SOURCE_DIR}/pico_novus.entitlements"
                        XCODE_ATTRIBUTE_ENABLE_HARDENED_RUNTIME "YES"
                    )
                endif()
            endif()

            if(DEBUG_APDU)
                target_compile_options(${PKCHT_TARGET} PRIVATE
                    -fsanitize=address
                    -g
                    -O1
                    -fno-omit-frame-pointer
                )
                target_link_options(${PKCHT_TARGET} PRIVATE
                    -fsanitize=address
                    -g
                    -O1
                    -fno-omit-frame-pointer
                )
            endif()
        endif()
    endif()
endfunction()

function(picokeys_add_macos_app_xcode_driver)
    set(options)
    set(oneValueArgs TARGET BUNDLE_ID SIGN_IDENTITY DEVELOPMENT_TEAM)
    cmake_parse_arguments(PKMXD "${options}" "${oneValueArgs}" "" ${ARGN})

    if(NOT PKMXD_TARGET)
        return()
    endif()
    if(NOT (APPLE AND ENABLE_EMULATION AND MACOS_APP AND NOT CMAKE_GENERATOR STREQUAL "Xcode" AND NOT MACOS_APP_XCODE_DRIVER))
        return()
    endif()
    if("${PKMXD_DEVELOPMENT_TEAM}" STREQUAL "")
        message(FATAL_ERROR "MACOS_APP=1 requires MACOS_APP_DEVELOPMENT_TEAM")
    endif()

    set(MACOS_APP_XCODE_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build-macos-app-xcode")
    set(MACOS_APP_XCODE_FORWARD_ARGS)
    get_cmake_property(_cache_vars CACHE_VARIABLES)
    foreach(_cv ${_cache_vars})
        if(_cv MATCHES "^(ENABLE_|DEBUG_APDU$|VIDPID$|USB_VID$|USB_PID$|USE_OPENSSL$|CMAKE_BUILD_TYPE$)")
            get_property(_cv_type CACHE ${_cv} PROPERTY TYPE)
            if(NOT _cv_type STREQUAL "INTERNAL")
                set(_cv_val "${${_cv}}")
                string(REPLACE ";" "\\;" _cv_val "${_cv_val}")
                list(APPEND MACOS_APP_XCODE_FORWARD_ARGS "-D${_cv}:${_cv_type}=${_cv_val}")
            endif()
        endif()
    endforeach()

    add_custom_target(${PKMXD_TARGET}_xcode ALL
        COMMAND cmake -S "${CMAKE_CURRENT_SOURCE_DIR}" -B "${MACOS_APP_XCODE_BUILD_DIR}" -G Xcode
                -DENABLE_EMULATION=1
                -DMACOS_APP=1
                -DMACOS_APP_XCODE_DRIVER=1
                -DMACOS_APP_BUNDLE_ID="${PKMXD_BUNDLE_ID}"
                -DMACOS_APP_SIGN_IDENTITY="${PKMXD_SIGN_IDENTITY}"
                -DMACOS_APP_DEVELOPMENT_TEAM="${PKMXD_DEVELOPMENT_TEAM}"
                ${MACOS_APP_XCODE_FORWARD_ARGS}
        COMMAND /bin/mkdir -p "${MACOS_APP_XCODE_BUILD_DIR}/Debug/include"
        COMMAND /bin/mkdir -p "${MACOS_APP_XCODE_BUILD_DIR}/build/pico_novus.build/Debug/DerivedSources-normal/arm64"
        COMMAND /bin/mkdir -p "${MACOS_APP_XCODE_BUILD_DIR}/build/pico_novus.build/Debug/DerivedSources/arm64"
        COMMAND /bin/mkdir -p "${MACOS_APP_XCODE_BUILD_DIR}/build/pico_novus.build/Debug/DerivedSources"
        COMMAND xcodebuild -allowProvisioningUpdates -project "${MACOS_APP_XCODE_BUILD_DIR}/${PKMXD_TARGET}.xcodeproj" -scheme "${PKMXD_TARGET}" -configuration Debug build
        COMMENT "Building signed ${PKMXD_TARGET}.app via Xcode"
        VERBATIM
    )
endfunction()

