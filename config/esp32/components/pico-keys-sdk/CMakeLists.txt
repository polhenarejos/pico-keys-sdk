set(PICO_KEYS_SDK_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../..)
idf_component_register(
    SRCS ${PICO_KEYS_SOURCES}
    INCLUDE_DIRS ${PICO_KEYS_SDK_DIR}/src ${PICO_KEYS_SDK_DIR}/src/fs ${PICO_KEYS_SDK_DIR}/src/rng ${PICO_KEYS_SDK_DIR}/src/usb ${PICO_KEYS_SDK_DIR}/src/led ${PICO_KEYS_SDK_DIR}/tinycbor/src ${PICO_KEYS_SDK_DIR}/mlkem/mlkem ${PICO_KEYS_SDK_DIR}/config/mlkem
    REQUIRES bootloader_support esp_partition esp_tinyusb efuse mbedtls mlkem512 mlkem768 mlkem1024 tinycbor
)
idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE ON)
