set(MLKEM_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../../third-party/mlkem/mlkem)

file(GLOB_RECURSE MLKEM_SOURCES
    ${MLKEM_DIR}/src/*.c
)
list(FILTER MLKEM_SOURCES EXCLUDE REGEX "/native/")

idf_component_register(
    SRCS ${MLKEM_SOURCES}
    INCLUDE_DIRS ${MLKEM_DIR}
)
idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE ON)

target_compile_definitions(${COMPONENT_LIB} PRIVATE
    MLK_CONFIG_PARAMETER_SET=1024
    MLK_CONFIG_MULTILEVEL_NO_SHARED
    MLK_CONFIG_NAMESPACE_PREFIX=mlkem
)

target_compile_options(${COMPONENT_LIB} PRIVATE
    -O2
    -fno-builtin
    -fno-strict-aliasing
)
