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

aux_source_directory(${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/QuoteGeneration/qcnl _srcs)
aux_source_directory(${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/QuoteGeneration/qcnl/linux _srcs)
add_library(sgx_default_qcnl_wrapper SHARED ${_srcs})

link_directories(
    ${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/prebuilt/openssl/lib/linux64
    ${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/tools/PCKCertSelection/static_out
)

target_include_directories(sgx_default_qcnl_wrapper PRIVATE
    ${SGX_HEADER_DIR}
    ${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/QuoteGeneration/qcnl/inc
    ${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/QuoteGeneration/pce_wrapper/inc
    ${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/QuoteGeneration/quote_wrapper/common/inc
    ${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/QuoteGeneration/common/inc/internal
    ${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/QuoteVerification/QVL/Src/ThirdParty/rapidjson/include/rapidjson
    ${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/prebuilt/openssl/inc
    ${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/tools/PCKCertSelection/include
)

add_dependencies(sgx_default_qcnl_wrapper PCKCertSelection)

set_property(TARGET sgx_default_qcnl_wrapper APPEND_STRING PROPERTY LINK_FLAGS " -Wl,-z,defs")
set_property(TARGET sgx_default_qcnl_wrapper APPEND_STRING PROPERTY LINK_DEPENDS  
        ${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/QuoteGeneration/qcnl/linux/sgx_default_qcnl.lds
    )
target_link_libraries(sgx_default_qcnl_wrapper
  oal crypto ${CMAKE_CURRENT_BINARY_DIR}/../lib/libPCKCertSelection.a
)

