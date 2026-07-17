#
# This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
# Copyright (c) 2022 Pol Henarejos.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#

cmake_minimum_required(VERSION 3.13)

project(picokeys_sdk_tests C)

set(CMAKE_C_STANDARD 11)

enable_testing()

set(OBJECT_CRYPTO_MBEDTLS_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/../third-party/mbedtls/library/aes.c
    ${CMAKE_CURRENT_LIST_DIR}/../third-party/mbedtls/library/ccm.c
    ${CMAKE_CURRENT_LIST_DIR}/../third-party/mbedtls/library/chacha20.c
    ${CMAKE_CURRENT_LIST_DIR}/../third-party/mbedtls/library/chachapoly.c
    ${CMAKE_CURRENT_LIST_DIR}/../third-party/mbedtls/library/cipher.c
    ${CMAKE_CURRENT_LIST_DIR}/../third-party/mbedtls/library/cipher_wrap.c
    ${CMAKE_CURRENT_LIST_DIR}/../third-party/mbedtls/library/constant_time.c
    ${CMAKE_CURRENT_LIST_DIR}/../third-party/mbedtls/library/des.c
    ${CMAKE_CURRENT_LIST_DIR}/../third-party/mbedtls/library/gcm.c
    ${CMAKE_CURRENT_LIST_DIR}/../third-party/mbedtls/library/hkdf.c
    ${CMAKE_CURRENT_LIST_DIR}/../third-party/mbedtls/library/md.c
    ${CMAKE_CURRENT_LIST_DIR}/../third-party/mbedtls/library/md5.c
    ${CMAKE_CURRENT_LIST_DIR}/../third-party/mbedtls/library/platform_util.c
    ${CMAKE_CURRENT_LIST_DIR}/../third-party/mbedtls/library/poly1305.c
    ${CMAKE_CURRENT_LIST_DIR}/../third-party/mbedtls/library/ripemd160.c
    ${CMAKE_CURRENT_LIST_DIR}/../third-party/mbedtls/library/sha1.c
    ${CMAKE_CURRENT_LIST_DIR}/../third-party/mbedtls/library/sha256.c
    ${CMAKE_CURRENT_LIST_DIR}/../third-party/mbedtls/library/sha512.c
)
add_library(object_crypto_mbedtls STATIC ${OBJECT_CRYPTO_MBEDTLS_SOURCES})
target_compile_definitions(object_crypto_mbedtls PUBLIC MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_LIST_DIR}/../config/mbedtls_config.h")
target_include_directories(object_crypto_mbedtls SYSTEM PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../third-party/mbedtls/include)

add_executable(object_store_test
    ${CMAKE_CURRENT_LIST_DIR}/../src/fs/object_store.c
    ${CMAKE_CURRENT_LIST_DIR}/../src/fs/object_store_txn.c
    ${CMAKE_CURRENT_LIST_DIR}/../src/fs/object_container.c
    ${CMAKE_CURRENT_LIST_DIR}/object_store_test.c
)
target_compile_definitions(object_store_test PRIVATE ENABLE_EMULATION)
target_include_directories(object_store_test PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../src ${CMAKE_CURRENT_LIST_DIR}/../src/fs)

if(MSVC)
    target_compile_options(object_store_test PRIVATE /W4 /WX)
else()
    target_compile_options(object_store_test PRIVATE -Wall -Wextra -Werror)
endif()

add_test(NAME object_store_test COMMAND object_store_test)

add_executable(object_crypto_provider_test
    ${CMAKE_CURRENT_LIST_DIR}/../src/fs/object_crypto_provider.c
    ${CMAKE_CURRENT_LIST_DIR}/object_crypto_provider_test.c
)
target_include_directories(object_crypto_provider_test PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../src ${CMAKE_CURRENT_LIST_DIR}/../src/fs)
target_link_libraries(object_crypto_provider_test PRIVATE object_crypto_mbedtls)

if(MSVC)
    target_compile_options(object_crypto_provider_test PRIVATE /W4 /WX)
else()
    target_compile_options(object_crypto_provider_test PRIVATE -Wall -Wextra -Werror)
endif()

add_test(NAME object_crypto_provider_test COMMAND object_crypto_provider_test)

add_executable(object_policy_test
    ${CMAKE_CURRENT_LIST_DIR}/../src/fs/object_policy.c
    ${CMAKE_CURRENT_LIST_DIR}/object_policy_test.c
)
target_include_directories(object_policy_test PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../src ${CMAKE_CURRENT_LIST_DIR}/../src/fs)
target_link_libraries(object_policy_test PRIVATE object_crypto_mbedtls)

if(MSVC)
    target_compile_options(object_policy_test PRIVATE /W4 /WX)
else()
    target_compile_options(object_policy_test PRIVATE -Wall -Wextra -Werror)
endif()

add_test(NAME object_policy_test COMMAND object_policy_test)
