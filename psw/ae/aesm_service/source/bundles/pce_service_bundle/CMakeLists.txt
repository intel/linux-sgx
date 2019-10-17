set(Edger8rOutputPCE "${CMAKE_CURRENT_BINARY_DIR}/pce_u.c")
get_filename_component(bundle ${CMAKE_CURRENT_SOURCE_DIR} NAME)
aux_source_directory(. _srcs)
link_directories(${CMAKE_SOURCE_DIR}/../../../../build/linux)
CreateBundle(${bundle} ${_srcs} ${Edger8rOutputPCE})

target_include_directories(${bundle} PRIVATE
	${PROJECT_SOURCE_DIR}/common
	${PROJECT_SOURCE_DIR}/../../../../common/inc/internal
	${SGX_HEADER_DIR}
	${PROJECT_SOURCE_DIR}/../../inc
	${PROJECT_SOURCE_DIR}/../../inc/internal
	${PROJECT_SOURCE_DIR}/../../pve
	${PROJECT_SOURCE_DIR}/../../../../external/epid-sdk
)

add_custom_command(
    OUTPUT ${Edger8rOutputPCE}
    COMMAND ${EDGER8R} --untrusted --untrusted-dir ${CMAKE_CURRENT_BINARY_DIR} ${PROJECT_SOURCE_DIR}/../../pce/pce.edl --search-path ${SGX_HEADER_DIR}
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_libraries(${bundle} oal urts_internal)
set_property(TARGET ${bundle} APPEND_STRING PROPERTY LINK_FLAGS " -Wl,-z,defs")
