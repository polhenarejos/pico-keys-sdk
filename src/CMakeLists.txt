idf_component_register(
    SRCS ${INTERNAL_SOURCES}
    INCLUDE_DIRS . fs rng usb
    PRIV_REQUIRES bootloader_support esp_partition
)
