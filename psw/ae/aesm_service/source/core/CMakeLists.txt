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

#Disable CET
if (CMAKE_COMPILER_IS_GNUCC AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 8)
  add_compile_options(-fcf-protection=none)
endif()

if(NOT US_BUILD_SHARED_LIBS)
  # Set up dependencies to resources from static bundles
  usFunctionGetResourceSource(TARGET aesm_service OUT _srcs)
endif()
add_executable(aesm_service ${_srcs})

target_include_directories(aesm_service PRIVATE
  ${PROJECT_SOURCE_DIR}/common
  ${PROJECT_SOURCE_DIR}/../../inc
  ${PROJECT_SOURCE_DIR}/../../inc/internal
  ${SGX_HEADER_DIR}
  ${PROJECT_SOURCE_DIR}/../../../../common/inc/internal
  ${PROJECT_SOURCE_DIR}/../../../../external/epid-sdk
  ${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/QuoteGeneration/quote_wrapper/common/inc
  ${PROJECT_SOURCE_DIR}/../../../../external/dcap_source/QuoteGeneration/quote_wrapper/quote/inc
  ${PROJECT_SOURCE_DIR}/interfaces
  ipc
)

add_subdirectory(ipc)
target_link_libraries(aesm_service
  CppMicroServices
  oal
  utils
  ipc
)

target_compile_definitions(aesm_service PRIVATE
    $<$<CONFIG:Debug>:DBG_LOG>
)

if(NOT US_BUILD_SHARED_LIBS)
  set(_static_bundles ${SUBDIRS})
  target_link_libraries(aesm_service ${_static_bundles})
  usFunctionEmbedResources(TARGET aesm_service
    # The executable is not a bundle itself but we still
    # need a bundle name for it here.
    BUNDLE_NAME aesm_service_bundle_name
    # Merge in all resources from static bundles
    ZIP_ARCHIVES ${_static_bundles}
    )
endif()
