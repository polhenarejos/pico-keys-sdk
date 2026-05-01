include(FetchContent)

option(ENABLE_EDDSA "Enable/disable EdDSA support" OFF)
configure_bool_option(
    ENABLE_EDDSA
    ""
    "EdDSA support:\t\t enabled"
    "EdDSA support:\t\t disabled"
)

set(MBEDTLS_PATH "${CMAKE_CURRENT_LIST_DIR}/../third-party/mbedtls")
set(TINYCBOR_PATH "${CMAKE_CURRENT_LIST_DIR}/../third-party/tinycbor")
set(CJSON_PATH "${CMAKE_CURRENT_LIST_DIR}/../third-party/cjson")
set(MLKEM_PATH "${CMAKE_CURRENT_LIST_DIR}/../third-party/mlkem")

set(PICOKEYS_MBEDTLS_STD_REPO "https://github.com/Mbed-TLS/mbedtls.git")
set(PICOKEYS_MBEDTLS_STD_REF "v3.6.6")
set(PICOKEYS_MBEDTLS_EDDSA_REPO "https://github.com/polhenarejos/mbedtls.git")
set(PICOKEYS_MBEDTLS_EDDSA_REF "mbedtls-3.6-eddsa")

set(PICOKEYS_TINYCBOR_REPO "https://github.com/intel/tinycbor.git")
set(PICOKEYS_TINYCBOR_REF "v0.6.1")
set(PICOKEYS_CJSON_REPO "https://github.com/DaveGamble/cJSON.git")
set(PICOKEYS_CJSON_REF "v1.7.19")
set(PICOKEYS_MLKEM_REPO "https://github.com/pq-code-package/mlkem-native.git")
set(PICOKEYS_MLKEM_REF "v1.1.0")

set(PICOKEYS_FETCH_DEPS_ON_DEMAND ON CACHE BOOL "Fetch third-party deps into pico-keys-sdk/third-party when missing")

function(picokeys_sync_dep name repo ref dest)
    set(_marker "${dest}/.picokeys_dep_source")
    set(_need_fetch OFF)

    if(NOT EXISTS "${dest}")
        if(NOT PICOKEYS_FETCH_DEPS_ON_DEMAND)
            message(FATAL_ERROR "${name} source code not found at ${dest}. Enable PICOKEYS_FETCH_DEPS_ON_DEMAND or provide the source tree manually.")
        endif()
        set(_need_fetch ON)
    else()
        set(_repo_ok OFF)
        set(_ref_ok OFF)
        if(EXISTS "${_marker}")
            file(STRINGS "${_marker}" _meta_lines)
            foreach(_line IN LISTS _meta_lines)
                if(_line STREQUAL "REPO=${repo}")
                    set(_repo_ok ON)
                endif()
                if(_line STREQUAL "REF=${ref}")
                    set(_ref_ok ON)
                endif()
            endforeach()
        endif()
        if(NOT _repo_ok OR NOT _ref_ok)
            set(_need_fetch ON)
        endif()
    endif()

    if(_need_fetch)
        message(STATUS "[deps] ${name}: repo=${repo} ref=${ref} status=updating (this may take a few seconds)")
        if(EXISTS "${dest}")
            file(REMOVE_RECURSE "${dest}")
        endif()
        execute_process(
            COMMAND git clone ${repo} ${dest}
            RESULT_VARIABLE _clone_rc
            OUTPUT_VARIABLE _clone_out
            ERROR_VARIABLE _clone_err
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_STRIP_TRAILING_WHITESPACE
        )
        if(NOT _clone_rc EQUAL 0)
            message(FATAL_ERROR "Failed to clone ${name} from ${repo}\nstdout: ${_clone_out}\nstderr: ${_clone_err}")
        endif()
        execute_process(
            COMMAND git -C ${dest} checkout ${ref}
            RESULT_VARIABLE _checkout_rc
            OUTPUT_VARIABLE _checkout_out
            ERROR_VARIABLE _checkout_err
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_STRIP_TRAILING_WHITESPACE
        )
        if(NOT _checkout_rc EQUAL 0)
            message(FATAL_ERROR "Failed to checkout ${name} ref ${ref}\nstdout: ${_checkout_out}\nstderr: ${_checkout_err}")
        endif()
        if(NOT EXISTS "${dest}")
            message(FATAL_ERROR "Failed to fetch ${name} into ${dest}")
        endif()
        file(WRITE "${_marker}" "REPO=${repo}\nREF=${ref}\n")
    else()
        message(STATUS "[deps] ${name}: repo=${repo} ref=${ref} status=cached")
    endif()
endfunction()

if(NOT ESP_PLATFORM)
    if(ENABLE_EDDSA)
        set(MBEDTLS_ORIGIN "${PICOKEYS_MBEDTLS_EDDSA_REPO}")
        set(MBEDTLS_REF "${PICOKEYS_MBEDTLS_EDDSA_REF}")

        add_compile_definitions(
            MBEDTLS_ECP_DP_ED25519_ENABLED=1
            MBEDTLS_ECP_DP_ED448_ENABLED=1
            MBEDTLS_EDDSA_C=1
            MBEDTLS_SHA3_C=1
        )
    else()
        set(MBEDTLS_ORIGIN "${PICOKEYS_MBEDTLS_STD_REPO}")
        set(MBEDTLS_REF "${PICOKEYS_MBEDTLS_STD_REF}")
    endif()

    picokeys_sync_dep(mbedtls_dep "${MBEDTLS_ORIGIN}" "${MBEDTLS_REF}" "${MBEDTLS_PATH}")
endif()

if(USB_ITF_HID)
    picokeys_sync_dep(tinycbor_dep "${PICOKEYS_TINYCBOR_REPO}" "${PICOKEYS_TINYCBOR_REF}" "${TINYCBOR_PATH}")
endif()
if(USB_ITF_LWIP)
    picokeys_sync_dep(cjson_dep "${PICOKEYS_CJSON_REPO}" "${PICOKEYS_CJSON_REF}" "${CJSON_PATH}")
endif()
if(ENABLE_PQC)
    picokeys_sync_dep(mlkem_dep "${PICOKEYS_MLKEM_REPO}" "${PICOKEYS_MLKEM_REF}" "${MLKEM_PATH}")
endif()
