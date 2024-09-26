#
# Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

set(qe3_logic "${CMAKE_SOURCE_DIR}/../../../../external/dcap_source/QuoteGeneration/build/linux/libsgx_qe3_logic.so")
set(qpl "${CMAKE_SOURCE_DIR}/../../../../external/dcap_source/QuoteGeneration/build/linux/libdcap_quoteprov.so")
set(qcnl "${CMAKE_SOURCE_DIR}/../../../../external/dcap_source/QuoteGeneration/build/linux/libsgx_default_qcnl_wrapper.so")
get_filename_component(bundle ${CMAKE_CURRENT_SOURCE_DIR} NAME)
aux_source_directory(. _src)
link_directories(${CMAKE_SOURCE_DIR}/../../../../build/linux
                 ${CMAKE_SOURCE_DIR}/../../../../external/dcap_source/QuoteGeneration/build/linux)
CreateBundle(${bundle} ${_src})

target_include_directories(${bundle} PRIVATE
	${PROJECT_SOURCE_DIR}/common
	${SGX_HEADER_DIR}
	${PROJECT_SOURCE_DIR}/../../../../common/inc/internal
	${PROJECT_SOURCE_DIR}/../../inc
	${PROJECT_SOURCE_DIR}/../../inc/internal
	${PROJECT_SOURCE_DIR}/../../../../external/epid-sdk
	${PROJECT_SOURCE_DIR}/../../../../external/ippcp_internal/inc
	${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/QuoteGeneration/quote_wrapper/quote/inc
	${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/QuoteGeneration/quote_wrapper/common/inc
	${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/QuoteGeneration/quote_wrapper/quote/enclave
	${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/QuoteGeneration/pce_wrapper/inc
	${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/QuoteGeneration/common/inc/internal
	${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/QuoteGeneration/common/inc/internal/linux
)

add_custom_command(OUTPUT ${qe3_logic}
    COMMAND make all
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/QuoteGeneration/quote_wrapper/quote/linux"
)

add_custom_command(OUTPUT ${qpl}
    COMMAND make all
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/QuoteGeneration/qpl/linux"
    DEPENDS ${qcnl}
)

add_custom_command(OUTPUT ${qcnl}
    COMMAND make all
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/QuoteGeneration/qcnl/linux"
)

add_custom_target(dcap_libs DEPENDS ${qe3_logic} ${qpl} ${qcnl})
target_link_libraries(${bundle} oal utils ${qe3_logic})
add_dependencies(${bundle} dcap_libs)
set_property(TARGET ${bundle} APPEND_STRING PROPERTY LINK_FLAGS " -Wl,-z,defs")
