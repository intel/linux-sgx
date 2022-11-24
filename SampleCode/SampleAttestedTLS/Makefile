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


include ./sgxenv.mk

.PHONY: all PREPARE_SGX_SSL build clean run

all: build 

# make sgxssl lib beforehand
PREPARE_SGXSSL := ./prepare_sgxssl.sh
SGXSSL_HEADER_CHECK := $(SGXSSL_PKG_PATH)/include/openssl/opensslconf.h
PREPARE_SGX_SSL:
	@chmod 755 $(PREPARE_SGXSSL)
	@test -f $(SGXSSL_PKG_PATH)/lib64/lib$(OpenSSL_Crypto_Library_Name).a && test -f $(SGXSSL_PKG_PATH)/lib64/lib$(OpenSSL_SSL_Library_Name).a && test -f $(SGXSSL_PKG_PATH)/lib64/lib$(SGXSSL_Library_Name).a && test -f $(SGXSSL_HEADER_CHECK) || $(PREPARE_SGXSSL)
	@$(info "NOTE: sgxssl prepared")

$(SGXSSL_HEADER_CHECK) : PREPARE_SGX_SSL

build: $(SGXSSL_HEADER_CHECK)
	$(MAKE) -C server
	$(MAKE) -C client
	$(MAKE) -C non_enc_client

tdx: $(SGXSSL_HEADER_CHECK)
	$(MAKE) -C server_tdx

clean:
	$(MAKE) -C server clean
	$(MAKE) -C client clean
	$(MAKE) -C non_enc_client clean
	$(MAKE) -C server_tdx clean

run:
	echo "Launch processes to establish an Attested TLS between two enclaves"
	./server/host/tls_server_host ./server/enc/tls_server_enclave.signed.so -port:12341 &
	sleep 2
	./client/host/tls_client_host ./client/enc/tls_client_enclave.signed.so -server:localhost -port:12341
	echo "Launch processes to establish an Attested TLS between an non-encalve TLS client and an TLS server running inside an enclave"
	./server/host/tls_server_host ./server/enc/tls_server_enclave.signed.so -port:12345 &
	sleep 2
	./non_enc_client/tls_non_enc_client -server:localhost -port:12345

run-server-in-loop:
	echo "Launch long-running Attested TLS server"
	./server/host/tls_server_host ./server/enc/tls_server_enclave.signed.so -port:12341 -server-in-loop
