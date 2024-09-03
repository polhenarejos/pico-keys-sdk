idf_component_register(
    SRCS ${INTERNAL_SOURCES}
    INCLUDE_DIRS . fs rng usb led ../mbedtls/include ../tinycbor/src
    REQUIRES bootloader_support esp_partition esp_tinyusb efuse
)
