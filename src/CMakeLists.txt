idf_component_register(
    SRCS ${PICO_KEYS_SOURCES}
    INCLUDE_DIRS . fs rng usb led ../tinycbor/src
    REQUIRES bootloader_support esp_partition esp_tinyusb efuse mbedtls
)
idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE ON)

# Add custom button pin configuration if enabled
if(DEFINED CUST_BUTTON_PIN AND CUST_BUTTON_PIN GREATER -1)
    target_compile_definitions(${COMPONENT_LIB} PUBLIC CUST_BUTTON_PIN=${CUST_BUTTON_PIN})
    message(STATUS "Custom button PIN configured: ${CUST_BUTTON_PIN}")
endif()
