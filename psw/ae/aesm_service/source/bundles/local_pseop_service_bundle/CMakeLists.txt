set(Edger8rOutputOP "${CMAKE_CURRENT_BINARY_DIR}/pse_op_u.h")
set(sqlite_src "${PROJECT_SOURCE_DIR}/../../../../external/sqlite/src/sqlite3.c")
get_filename_component(bundle ${CMAKE_CURRENT_SOURCE_DIR} NAME)
aux_source_directory(. _srcs)
link_directories(${CMAKE_SOURCE_DIR}/../../../../build/linux)
CreateBundle(${bundle} ${_srcs} ${sqlite_src} ${Edger8rOutputOP})

target_include_directories(${bundle} PRIVATE
	${PROJECT_SOURCE_DIR}/common
	${PROJECT_SOURCE_DIR}/../../../../common/inc/internal
	${PROJECT_SOURCE_DIR}/../../../../common/inc
	${PROJECT_SOURCE_DIR}/../../inc
	${PROJECT_SOURCE_DIR}/../../inc/internal
	${PROJECT_SOURCE_DIR}/../../pse/pse_op
	${PROJECT_SOURCE_DIR}/../../../../external/epid-sdk
	${PROJECT_SOURCE_DIR}/../../../../external/DALSdk/JHI/linux
	${PROJECT_SOURCE_DIR}/../../../../external/sqlite/src
	${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/QuoteGeneration/quote_wrapper/common/inc
	${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/QuoteGeneration/quote_wrapper/quote/inc
	${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/QuoteGeneration/pce_wrapper/inc
)

add_custom_command(
    OUTPUT ${Edger8rOutputOP}
    COMMAND ${PROJECT_SOURCE_DIR}/../../../../build/linux/sgx_edger8r --untrusted --untrusted-dir ${CMAKE_CURRENT_BINARY_DIR} ${PROJECT_SOURCE_DIR}/../../pse/pse_op/pse_op.edl --search-path ${PROJECT_SOURCE_DIR}/../../../../common/inc
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_libraries(${bundle} oal utils urts_internal)
set_property(TARGET ${bundle} APPEND_STRING PROPERTY LINK_FLAGS " -Wl,-z,defs")
