idf_component_register(
    SRCS ${PICO_KEYS_SOURCES}
    INCLUDE_DIRS . fs rng usb led ../tinycbor/src
    REQUIRES bootloader_support esp_partition esp_tinyusb efuse mbedtls
)
idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE ON)
