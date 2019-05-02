set(Edger8rOutputPR "${CMAKE_CURRENT_BINARY_DIR}/pse_pr_u.h")
set(PSEPRCommon "${CMAKE_SOURCE_DIR}/../../common/pse_pr_common.cpp")
set(SIGRLCommon "${CMAKE_SOURCE_DIR}/../../common/se_sig_rl.cpp")
set(TSealCommon "${CMAKE_SOURCE_DIR}/../../../../sdk/tseal/tSeal_util.cpp")
get_filename_component(bundle ${CMAKE_CURRENT_SOURCE_DIR} NAME)
aux_source_directory(. _srcs)
aux_source_directory(BackendInterface BackendInterface_srcs)
link_directories(${CMAKE_SOURCE_DIR}/../../../../build/linux)
CreateBundle(${bundle} ${_srcs} ${BackendInterface_srcs} ${PSEPRCommon} ${SIGRLCommon} ${TSealCommon} ${Edger8rOutputPR})

target_include_directories(${bundle} PRIVATE
	${PROJECT_SOURCE_DIR}/common
	${PROJECT_SOURCE_DIR}/../../../../common/inc/internal
	${PROJECT_SOURCE_DIR}/../../../../common/inc
	${PROJECT_SOURCE_DIR}/../../inc
	${PROJECT_SOURCE_DIR}/../../inc/internal
	${PROJECT_SOURCE_DIR}/../../pve
	${PROJECT_SOURCE_DIR}/../../../../external/epid-sdk
)

add_custom_command(
    OUTPUT ${Edger8rOutputPR}
    COMMAND ${PROJECT_SOURCE_DIR}/../../../../build/linux/sgx_edger8r --untrusted --untrusted-dir ${CMAKE_CURRENT_BINARY_DIR} ${PROJECT_SOURCE_DIR}/../../pse/pse_pr/pse_pr.edl --search-path ${PROJECT_SOURCE_DIR}/../../../../common/inc
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_libraries(${bundle} oal utils urts_internal)
set_property(TARGET ${bundle} APPEND_STRING PROPERTY LINK_FLAGS " -Wl,-z,defs")
