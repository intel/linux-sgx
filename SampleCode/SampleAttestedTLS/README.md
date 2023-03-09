## Prerequisites
 The audience is assumed to be familiar:
 [What is an Attested TLS channel](AttestedTLSREADME.md#what-is-an-attested-tls-channel)

 The `QuoteGenerationSample` and `QuoteVerificationSample` can be run successfully on server and client machines. (`tdx-quote-generation-sample` and `tdx-quote-verification-sample` for TDX)
# The Attested TLS sample

It has the following properties:

- Demonstrates attested TLS feature
  - between two enclaves
  - between an enclave application and a non enclave application
- Use of SgxSSL libraries inside enclaves for TLS
- Use of following Enclave APIs
  - tee_get_certificate_with_evidence
  - tee_free_certificate
  - tee_verify_certificate_with_evidence
  - tee_verify_certificate_with_evidence_host

**Note: Currently this sample only works on SGX-FLC systems.** The underlying SGX library support for end-to-end remote attestation is required but available only on SGX-FLC system. There is no plan to back port those libraries to either SGX1 system or software emulator.

**Additional Notes to this Sample:
- Only ECDSA attestation is supported.
- To make sure you can run this sample successfully, please refer to the samples in Intel(R) SGX DCAP repo:
    https://github.com/intel/SGXDataCenterAttestationPrimitives
  Steps in Readme in the 2 samples - QuoteGenerationSample and QuoteVerificationSample also apply to this sample.
  Please make sure the above 2 samples work good before you make and run this project.

## Overall Sample Configuration

This sample demonstrates 2 types of TLS channels
- Attested TLS channel between two enclaves
  - Both TLS client and server are hosted in enclave
- Attested TLS channel between a non enclave application and an enclave
  - TLS server is hosted in enclave, TLS client is hosted in non-enclave environment

Note: Both of them can run on the same machine or separate machines.

### Server application
  - Host part (tls_server_host)
    - Instantiate an enclave before transitioning the control into the enclave via an ecall.
  - Enclave (tls_server_enclave.signed.so)
    - Call tee_get_certificate_with_evidence to generate a certificate
    - Use SgxSSL API to configure a TLS server using the generated certificate
    - Launch a TLS server and wait for client connection request
    - Read client payload and reply with server payload
  - How to launch a server instance
```
./server/host/tls_server_host ./server/enc/tls_server_enclave.signed.so -port:12341
```
### Enclave Client application
  - Host part (tls_client_host)
    - Instantiate an enclave before transitioning the control into the enclave via an ecall.
  - Enclave (tls_client_enclave.signed.so)
    - Connect to server port via socket
    - Use SgxSSL API to configure a TLS client
    - Call tee_verify_certificate_with_evidence to verify the certificate and SGX ECDSA quote
    - Call tee_get_certificate_with_evidence to generate an certificate as client's certificate
    - Send client payload and wait for server's payload
  - How to launch a client instance
```
./client/host/tls_client_host ./client/enc/tls_client_enclave.signed.so -server:localhost -port:12341
```

### Non-enclave Client application
 - When used in this scenario, this non-enclave client is assumed to be a trusted party holding secrets and only shares it with the server after the server is validated
 - Connect to server port via socket
 - Use OpenSSL API to configure a TLS client
 - Call tee_verify_certificate_with_evidence_host to verify the certificate and SGX ECDSA quote
 - Send client payload and wait for server's payload

```
./non_enc_client/tls_non_enc_client -server:localhost -port:12341
```

## TDX Sample Configration

The sample supports creating attested TLS channel between:
- two TD-guests
- TD-guest and SGX enclave
- TD-guest and non TEE environment

> **Note**: 
> In order to connect to the port on guest TD from host or other machihnes, port forwarding needs to be set using QEMU command when starting the guest TD.  
Use the following QEMU command:
>```
>hostfwd=tcp::HOSTPORT-:GUESTPORT
>```

### TDX server application

  - Call tee_get_certificate_with_evidence to generate a certificate
  - Use OpenSSL API to configure a TLS server using the generated certificate
  - Launch a TLS server and wait for client connection request
  - Read client payload and reply with server payload
  - To run TDX server application, copy `./server_tdx/tls_server` to TD-guest and run the following command:

  ```
./tls_server -port:12341
  ```

### TDX client application

The TDX client applicaiton is the same as non-enclave client application, except that it is running in guest TD.

## Build and run
  ```bash
  make
  make run
  ```

Note:
  - Intel(R) ECDSA quote generation will load Intel(R) signed PCE, QE, which need to be run with an uid in `sgx_prv` group. Use below command to add the user running the process to `sgx_prv` group, then try to launch application again:
    $ sudo usermod -a -G sgx_prv <user name>
  - This sample has a dependency on the socket support, included in this project directory sgx_socket.
  - Option SGX_DEBUG is provided here to disable or enable debug symbols in the object file.
    Use it with make command:
    "make SGX_DEBUG=0" to turn off debug symbols, and "make SGX_DEBUG=1" to turn on debug symbols.
  - TLS support is provided by intel-sgx-ssl project on the branch support_tls.
    Repo URL: https://github.com/intel/intel-sgx-ssl/tree/support_tls
    Currently the branch only provides basic functions for TLS session between server and client inside enclave
    running in this sample.
    The project has a pre-preparation script - prepare_sgxssl.sh to prepare the SgxSSL libraries and link to them in
    the Makefile.
    Note that script "prepare_sgxssl.sh" requires git installed and configured.
  - Limitation: No Simulation mode is supported.

### Running attested TLS server in loop
By default the server exits after completing a TLS session with a client. `-server-in-loop` run-time option changes this behavior to allow the TLS server to handle multiple client requests.

```bash
./server/host/tls_server_host ./server/enc/tls_server_enclave.signed.so -port:12341 -server-in-loop
or
make run-server-in-loop
```

### Recommended TLS configurations when using OpenSSL

  It is strongly recommended that developers configure OpenSSL to restrict the TLS versions, cipher suites and elliptic curves to be used for TLS connections to enclave:

  - TLS protocol versions
    - TLS 1.2
    - TLS 1.3
  - TLS 1.3 cipher suites (in the exact order)
    - TLS13-AES-256-GCM-SHA384
    - TLS13-AES-128-GCM-SHA256
  - TLS 1.2 cipher suites (in the exact order)
    - ECDHE-ECDSA-AES128-GCM-SHA256
    - ECDHE-ECDSA-AES256-GCM-SHA384
    - ECDHE-RSA-"AES128-GCM-SHA256
    - ECDHE-RSA-AES256-GCM-SHA384
    - ECDHE-ECDSA-AES128-SHA256
    - ECDHE-ECDSA-AES256-SHA384
    - ECDHE-RSA-AES128-SHA256
    - ECDHE-RSA-AES256-SHA384
  - Elliptic curves
    - P-521
    - P-384
    - P-256

  This sample illustrates how to use [`initalize_ssl_context()`](common/openssl_utility.cpp#L118) to configure the `SSL_CTX` as suggested in both the [server](server/enc/openssl_server.cpp#L147) and the [client](client/enc/openssl_client.cpp#L200) modules.
