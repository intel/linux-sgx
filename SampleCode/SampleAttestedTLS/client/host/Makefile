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

include ../../sgxenv.mk

INCDIR=$(SGX_SDK)/include
SOCKETINCDIR = $(SOCKET_DIR)/include
SSLINCDIR = $(SGXSSL_PKG_PATH)/include
TLSINCDIR = $(SGXTLS_DIR)/include

all: build

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	$(SGX_EDGER8R) --untrusted ../tls_client.edl \
		--search-path $(INCDIR) \
		--search-path . \
		--search-path $(SOCKETINCDIR) \
		--search-path $(SSLINCDIR) \
		--search-path $(TLSINCDIR) \
		--search-path ../../common

	$(CC) -c $(App_C_Flags) tls_client_u.c
	$(CXX) -c -DM_TLS_CLIENT $(App_Cpp_Flags) host.cpp ../../sgx_socket/untrusted_sgx_socket.cpp ../../common/ucommon.cpp
	$(CXX) -o tls_client_host host.o untrusted_sgx_socket.o tls_client_u.o ucommon.o $(App_Link_Flags)

clean:
	rm -f tls_client_host *.o tls_client_u.* tls_client_args.h
