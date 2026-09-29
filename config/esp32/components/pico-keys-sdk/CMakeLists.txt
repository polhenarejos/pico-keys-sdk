set(PICOKEYS_SDK_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../..)

set(PICOKEYS_INCLUDE_DIRS
    ${PICOKEYS_SDK_DIR}/src
    ${PICOKEYS_SDK_DIR}/src/fs
    ${PICOKEYS_SDK_DIR}/src/otp
    ${PICOKEYS_SDK_DIR}/src/rng
    ${PICOKEYS_SDK_DIR}/src/usb
    ${PICOKEYS_SDK_DIR}/src/led
    ${PICOKEYS_SDK_DIR}/third-party/mbedtls/include
)

set(PICOKEYS_REQUIRES
    bootloader_support
    app_update
    esp_partition
    spi_flash
    esp_tinyusb
    efuse
    mbedtls
)
if(USB_ITF_HID)
    list(APPEND PICOKEYS_REQUIRES
        tinycbor
    )
endif()

if (USB_ITF_LWIP)
    list(APPEND PICOKEYS_REQUIRES
        lwip
        cjson
    )
endif()

if(ENABLE_PQC)
    list(APPEND PICOKEYS_INCLUDE_DIRS
        ${PICOKEYS_SDK_DIR}/third-party/mlkem/mlkem
        ${PICOKEYS_SDK_DIR}/config/mlkem
        ${PICOKEYS_SDK_DIR}/third-party/mldsa/mldsa
        ${PICOKEYS_SDK_DIR}/config/mldsa
    )
    list(APPEND PICOKEYS_REQUIRES
        mlkem512
        mlkem768
        mlkem1024
        mldsa44
        mldsa65
        mldsa87
    )
endif()

idf_component_register(
    SRCS ${PICOKEYS_SOURCES}
    INCLUDE_DIRS ${PICOKEYS_INCLUDE_DIRS}
    REQUIRES ${PICOKEYS_REQUIRES}
)

idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE ON)
