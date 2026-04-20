set(PICOKEYS_SDK_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../..)

idf_component_register(
    SRCS ${CJSON_SOURCES}
    INCLUDE_DIRS ${PICOKEYS_SDK_DIR}/third-party/cjson
)

idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE ON)
