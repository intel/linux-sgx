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

include ../sgxenv.mk

Server_Include_Path := -I. -I$(SGX_SDK)/include -I/usr/include/openssl 
Server_Cpp_Flags := -DCLIENT_USE_QVL $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(Server_Include_Path)

ifeq ($(SGX_DEBUG), 1)
	Server_Cpp_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Server_Cpp_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
	Server_Cpp_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

Server_Cpp_Flags += -std=c++11

Server_Link_Flags := $(SGX_COMMON_CFLAGS) -L. -lssl \
	-L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lsgx_utls \
	-lsgx_dcap_ql -lsgx_dcap_quoteverify -lcrypto

.PHONY: all build clean #run

all: build

build:
	$(CXX) -c -DTDX_ENV -DCLIENT_USE_QVL $(Server_Cpp_Flags) server.cpp openssl_server.cpp ../common/verify_callback.cpp ../common/utility.cpp ../common/openssl_utility.cpp ../common/err_msg.cpp
	$(CXX) -o tls_server server.o openssl_server.o verify_callback.o utility.o openssl_utility.o err_msg.o $(Server_Link_Flags) -lssl -ltdx_tls -lsgx_dcap_quoteverify -ltdx_attest

clean:
	rm -f tls_server *.o
