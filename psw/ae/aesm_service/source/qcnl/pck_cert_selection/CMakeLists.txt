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

set(pck_cert_selection_dir
  ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../external/dcap_source/tools/PCKCertSelection/PCKCertSelectionLib
)

set(CMAKE_CXX_FLAGS "-DATTESTATIONPARSERS_STATIC -DPCK_CERT_SELECTION_WITH_COMPONENT -DIS_STATIC_LIB")


set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -fvisibility=hidden -fvisibility-inlines-hidden -Werror -DLINUX -m64 -fstack-protector -D_FORTIFY_SOURCE=2 -UDEBUG -DNDEBUG -ffunction-sections -fdata-sections -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type -Waddress -Wsequence-point -Wformat-security -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow -Wcast-align -Wconversion -Wredundant-decls -DITT_ARCH_IA64 -std=c++14")

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(QVL_DIR "${pck_cert_selection_dir}/../../../QuoteVerification/QVL/Src")
# QG root directory
# include the se_version.h file from there

set(QG_DIR "${pck_cert_selection_dir}/../../../QuoteGeneration")
# openssl include dir
set(OPENSSL_INC "${pck_cert_selection_dir}/../../../prebuilt/openssl/inc")
# openssl lib dir
set(OPENSSL_LIB "${pck_cert_selection_dir}/../../../prebuilt/openssl/lib/linux64")

# JSON parser include dir
set(JSON_INC "${QVL_DIR}/ThirdParty/rapidjson/include")

# QVL Attestation Parsers include directory
set(PARSERS_INC "${QVL_DIR}/AttestationParsers/include")
set(PARSERS_COMM_INC "${QVL_DIR}/AttestationCommons/include")
set(PARSERS_UTIL_INC "${QVL_DIR}/AttestationCommons/include/Utils")



######## Library Settings ########

# QVL Attestation Parsers source dirs
set(PARSERS_DIR     "${QVL_DIR}/AttestationParsers/src")
set(PARSERS_COMM_DIR    "${QVL_DIR}/AttestationCommons/src")
set(JSON_DIR    "${PARSERS_DIR}/Json")
set(X509_DIR    "${PARSERS_DIR}/X509")
set(HELPERS_DIR     "${PARSERS_DIR}/OpensslHelpers")
set(UTILS_DIR     "${PARSERS_COMM_DIR}/Utils")
set(VER_DIR       "${QG_DIR}/common/inc/internal")

# source files from QVL Attestation Parsers dirs
set(PARSER_CPP_FILES
  ${PARSERS_DIR}/ParserUtils.cpp
  )
set(X509_CPP_FILES
  ${X509_DIR}/Certificate.cpp 
  ${X509_DIR}/DistinguishedName.cpp
  ${X509_DIR}/Extension.cpp
  ${X509_DIR}/PckCertificate.cpp
  ${X509_DIR}/Signature.cpp
  ${X509_DIR}/Tcb.cpp
  ${X509_DIR}/Validity.cpp
  )
set(HELPERS_CPP_FILES
  ${HELPERS_DIR}/OidUtils.cpp
  )
set(JSON_CPP_FILES
  ${JSON_DIR}/JsonParser.cpp
  ${JSON_DIR}/TcbInfo.cpp
  ${JSON_DIR}/TcbLevel.cpp
  ${JSON_DIR}/TdxModule.cpp
  ${JSON_DIR}/TcbComponent.cpp
  ${JSON_DIR}/TdxModuleTcb.cpp
  ${JSON_DIR}/TdxModuleTcbLevel.cpp
  ${JSON_DIR}/TdxModuleIdentity.cpp
  )
set(UTILS_CPP_FILES
  ${UTILS_DIR}/GMTime.cpp
  ${UTILS_DIR}/TimeUtils.cpp
  )
set(LOCAL_CPP_FILES
  ${pck_cert_selection_dir}/pck_sorter.cpp
  ${pck_cert_selection_dir}/pck_cert_selection.cpp
  ${pck_cert_selection_dir}/config_selector.cpp
  ${pck_cert_selection_dir}/tcb_manager.cpp
)


add_library(PCKCertSelection STATIC
  ${PARSER_CPP_FILES}
  ${X509_CPP_FILES}
  ${HELPERS_CPP_FILES}
  ${JSON_CPP_FILES}
  ${UTILS_CPP_FILES}
  ${LOCAL_CPP_FILES}
)

# add the path to the search path for include files
target_include_directories(PCKCertSelection PRIVATE
  ${OPENSSL_INC}
  ${JSON_INC}
  ${PARSERS_INC}
  ${PARSERS_COMM_INC}
  ${PARSERS_DIR}
  ${VER_DIR}
  ${PARSERS_UTIL_INC}
  ${pck_cert_selection_dir}/../include
)
 
set_target_properties(PCKCertSelection PROPERTIES COMPILE_OPTIONS "-Wno-overloaded-virtual")
