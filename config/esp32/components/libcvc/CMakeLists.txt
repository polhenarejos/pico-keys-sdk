set(PICOKEYS_SDK_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../..)

idf_component_register(
    SRCS ${LIBCVC_SOURCES}
    INCLUDE_DIRS ${PICOKEYS_SDK_DIR}/third-party/libcvc/src ${PICOKEYS_SDK_DIR}/third-party/libcvc/include
    REQUIRES mbedtls
)

idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE ON)
