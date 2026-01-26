set(PICO_KEYS_SDK_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../..)
idf_component_register(
    SRCS ${CBOR_SOURCES}
    INCLUDE_DIRS ${PICO_KEYS_SDK_DIR}/tinycbor/src
)
idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE ON)
