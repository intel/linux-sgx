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

# [proj-begin]
cmake_minimum_required(VERSION 3.0.0)
project(ModularAESM VERSION 0.1.0)


#set(CMAKE_MODULE_PATH "path to CppMicroServicesConfig.cmake" ${CMAKE_MODULE_PATH})


# check if protobuf was found
find_package(Protobuf REQUIRED)
if(PROTOBUF_FOUND)
    message ("protobuf found")
else()
    message (FATAL_ERROR "Cannot find Protobuf")
endif()

# check if CppMicroServices was found
set(CppMicroServices_DIR ../../../../external/CppMicroServices/local-install/share/cppmicroservices4/cmake)
find_package(CppMicroServices NO_MODULE REQUIRED)
cmake_minimum_required(VERSION ${US_CMAKE_MINIMUM_REQUIRED_VERSION})
cmake_policy(VERSION ${US_CMAKE_MINIMUM_REQUIRED_VERSION})
if(CppMicroServices_FOUND)
    message ("CppMicroServices found")
else()
    message (FATAL_ERROR "Cannot find CppMicroServices")
endif()

if(REF_LE)
  add_definitions("-DREF_LE")
endif()

set(CMAKE_CXX_STANDARD_REQUIRED 1)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_SKIP_BUILD_RPATH true)

########## SGX SDK Settings ##########
set(SGX_ARCH x64)
execute_process (
    COMMAND getconf LONG_BIT
    OUTPUT_VARIABLE LONG_BIT
)

if(${LONG_BIT} EQUAL 32)
    set(SGX_ARCH x86)
else()
    string(FIND "${CMAKE_CXX_FLAGS}" "-m32" M32_FLAG)
    if (${M32_FLAG} GREATER -1)
        set(SGX_ARCH x86)
    endif()
endif()

if(DEFINED ENV{SGX_SDK})
    message ("SGX_SDK environment variable defined: " $ENV{SGX_SDK})
else()
    message ("SGX_SDK environment variable not defined, will be set to /opt/intel/sgxsdk")
    set(ENV{SGX_SDK} /opt/intel/sgxsdk)
endif()

FILE(GLOB RESULT $ENV{SGX_SDK})
LIST(LENGTH RESULT RES_LEN)
if(RES_LEN EQUAL 0)
    set(SGX_HEADER_DIR /usr/include/sgxsdk)
    set(SGX_LIB_DIR /usr/lib/sgxsdk)
    set(SGX_BIN_DIR /usr/bin)
else()
    set(SGX_HEADER_DIR $ENV{SGX_SDK}/include)

    if(${SGX_ARCH} STREQUAL x86)
        set(SGX_LIB_DIR $ENV{SGX_SDK}/lib)
        set(SGX_BIN_DIR $ENV{SGX_SDK}/bin/x86)
    else()
        set(SGX_LIB_DIR $ENV{SGX_SDK}/lib64)
        set(SGX_BIN_DIR $ENV{SGX_SDK}/bin/x64)
    endif()
endif()
set(SGXSIGN ${SGX_BIN_DIR}/sgx_sign)
set(EDGER8R ${SGX_BIN_DIR}/sgx_edger8r)
######################################

set(ModularAESM_ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/lib")
set(ModularAESM_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin")
set(ModularAESM_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin")

foreach(_type ARCHIVE LIBRARY RUNTIME)
  if(NOT CMAKE_${_type}_OUTPUT_DIRECTORY)
    set(CMAKE_${_type}_OUTPUT_DIRECTORY ${ModularAESM_${_type}_OUTPUT_DIRECTORY})
  endif()
endforeach()
#[proj-end]

MACRO(BUNDLELIST result curdir)
  FILE(GLOB children RELATIVE ${curdir} ${curdir}/*)
  SET(dirlist "")
  FOREACH(child ${children})
    IF(IS_DIRECTORY ${curdir}/${child})
      LIST(APPEND dirlist ${child})
    ENDIF()
  ENDFOREACH()
  SET(${result} ${dirlist})
ENDMACRO()

function(CreateBundle _name)
  set(_srcs ${ARGN})

  usFunctionGetResourceSource(TARGET ${_name} OUT _srcs)
  usFunctionGenerateBundleInit(TARGET ${_name} OUT _srcs)

  add_library(${_name} ${_srcs})
  target_include_directories(${_name} PRIVATE
    ${PROJECT_SOURCE_DIR}/interfaces
    ${CMAKE_CURRENT_BINARY_DIR}
    ${PROJECT_SOURCE_DIR}/../../data/constants/linux
  )

  set(_bundle_name ${_name}_name)
  target_compile_definitions(${_name} PRIVATE
      $<$<CONFIG:Debug>:DBG_LOG>
      US_BUNDLE_NAME=${_bundle_name}
  )
  target_link_libraries(${_name} ${CppMicroServices_LIBRARIES})

  set_target_properties(${_name} PROPERTIES
    US_BUNDLE_NAME ${_bundle_name}
  )
  if(BUILD_SHARED_LIBS)
    set_target_properties(${_name} PROPERTIES
      CXX_VISIBILITY_PRESET hidden
      VISIBILITY_INLINES_HIDDEN 1
    )
    set_target_properties(${_name} PROPERTIES
      LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin/bundles"
    )
  endif()

  usFunctionEmbedResources(TARGET ${_name}
  WORKING_DIRECTORY
    ${CMAKE_CURRENT_SOURCE_DIR}
  FILES
    manifest.json
  )
endfunction()

ADD_SUBDIRECTORY(oal)
ADD_SUBDIRECTORY(utils)
ADD_SUBDIRECTORY(core)
ADD_SUBDIRECTORY(bundles)
