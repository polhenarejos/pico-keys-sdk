set(MLDSA_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../../third-party/mldsa/mldsa)

file(GLOB_RECURSE MLDSA_SOURCES
    ${MLDSA_DIR}/src/*.c
)
list(FILTER MLDSA_SOURCES EXCLUDE REGEX "/native/")

idf_component_register(
    SRCS ${MLDSA_SOURCES}
    INCLUDE_DIRS ${MLDSA_DIR}
)
idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE ON)

target_compile_definitions(${COMPONENT_LIB} PRIVATE
    MLD_CONFIG_PARAMETER_SET=87
    MLD_CONFIG_MULTILEVEL_WITH_SHARED
    MLD_CONFIG_NAMESPACE_PREFIX=mldsa
)

target_compile_options(${COMPONENT_LIB} PRIVATE
    -O2
    -fno-builtin
    -fno-strict-aliasing
)
