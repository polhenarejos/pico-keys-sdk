idf_component_register(
    SRCS ${INTERNAL_SOURCES}
    INCLUDE_DIRS . fs rng usb ../mbedtls/include
    REQUIRES bootloader_support esp_partition tinyusb
)
