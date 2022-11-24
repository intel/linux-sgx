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

Client_Include_Path := -I. -I$(SGX_SDK)/include -I/usr/include/openssl 
Client_Cpp_Flags := -DCLIENT_USE_QVL $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(Client_Include_Path)

ifeq ($(SGX_DEBUG), 1)
	Client_Cpp_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Client_Cpp_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
	Client_Cpp_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

Client_Cpp_Flags += -std=c++11

Client_Link_Flags := $(SGX_COMMON_CFLAGS) -L. -lssl \
	-L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lsgx_utls \
	-lsgx_dcap_ql -lsgx_dcap_quoteverify -lcrypto

.PHONY: all build clean #run

all: build

build:
	$(CXX) -c $(Client_Cpp_Flags) client.cpp ../common/err_msg.cpp ../common/verify_callback.cpp
	$(CXX) -o tls_non_enc_client client.o err_msg.o verify_callback.o $(Client_Link_Flags) 

clean:
	rm -f tls_non_enc_client *.o

run:
	./tls_non_enc_client -server:localhost -port:12341
