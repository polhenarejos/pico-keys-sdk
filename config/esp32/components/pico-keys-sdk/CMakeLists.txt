set(PICOKEYS_SDK_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../..)

set(PICOKEYS_INCLUDE_DIRS
    ${PICOKEYS_SDK_DIR}/src
    ${PICOKEYS_SDK_DIR}/src/fs
    ${PICOKEYS_SDK_DIR}/src/otp
    ${PICOKEYS_SDK_DIR}/src/rng
    ${PICOKEYS_SDK_DIR}/src/usb
    ${PICOKEYS_SDK_DIR}/src/led
)

set(PICOKEYS_REQUIRES
    bootloader_support
    esp_partition
    esp_tinyusb
    efuse
    mbedtls
    tinycbor
    lwip
    cjson
)

if(ENABLE_PQC)
    list(APPEND PICOKEYS_INCLUDE_DIRS
        ${PICOKEYS_SDK_DIR}/third-party/mlkem/mlkem
        ${PICOKEYS_SDK_DIR}/config/mlkem
    )
    list(APPEND PICOKEYS_REQUIRES
        mlkem512
        mlkem768
        mlkem1024
    )
endif()

idf_component_register(
    SRCS ${PICOKEYS_SOURCES}
    INCLUDE_DIRS ${PICOKEYS_INCLUDE_DIRS}
    REQUIRES ${PICOKEYS_REQUIRES}
)

idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE ON)
