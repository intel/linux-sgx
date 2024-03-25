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

aux_source_directory(. _srcs)
add_library(utils SHARED ${_srcs}
    "../../../../../common/src/sgx_read_rand.cpp"
    "../../../../../common/src/sgx_memset_s.cpp"
    "../../../../../common/src/crypto_cmac_128.cpp")

if(NOT "${USE_PREBUILT_OPENSSL}" STREQUAL "1")
    set(CRYPTO_INC ${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/prebuilt/openssl/inc)
    set(CRYPTO_LIB ${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/prebuilt/openssl/lib/linux64/libcrypto.a)
else()
    set(CRYPTO_LIB crypto)
endif()

target_include_directories(utils PRIVATE
    ${PROJECT_SOURCE_DIR}/common
    ${PROJECT_SOURCE_DIR}/common/oal
    ${PROJECT_SOURCE_DIR}/../../inc
    ${PROJECT_SOURCE_DIR}/../../inc/internal
    ${SGX_HEADER_DIR}
    ${PROJECT_SOURCE_DIR}/../../../../common/inc/internal
    ${PROJECT_SOURCE_DIR}/../../../../external/epid-sdk
    ${PROJECT_SOURCE_DIR}/../../../../external/rdrand
    ${PROJECT_SOURCE_DIR}/../../data/constants/linux
    ${CRYPTO_INC}
)

target_compile_definitions(utils PRIVATE
  $<$<CONFIG:Debug>:DBG_LOG>
)

set_property(TARGET utils APPEND_STRING PROPERTY LINK_FLAGS " -Wl,-z,defs")

target_link_libraries(utils
    ${CRYPTO_LIB}
    oal
    ${CMAKE_SOURCE_DIR}/../../../../external/rdrand/src/librdrand.a
)

