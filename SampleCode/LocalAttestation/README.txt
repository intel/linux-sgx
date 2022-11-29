---------------------------
The project aims to demo SGX local attestation flow. 

------------------------------------
How to Build the Sample Code
------------------------------------
1. Install Intel(R) Software Guard Extensions (Intel(R) SGX) SDK for Linux* OS
2. Enclave test key(two options):
    a. Install openssl first, then the project will generate a test key<EnclaveInitiator_private_test.pem>/<EnclaveResponder_private_test.pem> automatically when you build the project.
    b. Rename your test key(3072-bit RSA private key) to <EnclaveInitiator_private_test.pem>/<EnclaveResponder_private_test.pem> and put it under the <EnclaveInitiator>/<EnclaveResponder> folder.
3. Build the project with the prepared Makefile:
        a. Hardware Mode, Debug build:
		$ make
        b. Hardware Mode, Pre-release build:
		$ make SGX_PRERELEASE=1 SGX_DEBUG=0
        c. Hardware Mode, release build:
		$ make SGX_DEBUG=0
        d. Simulation Mode, Debug build:
		$ make SGX_MODE=SIM
        e. Simulation Mode, Pre-release build:
		$ make SGX_MODE=SIM SGX_PRERELEASE=1 SGX_DEBUG=0
        f. Simulation Mode, Release build:
		$ make SGX_MODE=SIM SGX_DEBUG=0
        g. Use Local Attestation 2.0 protocol, Hardware Mode, Debug build:
        $ make LAv2=1
           Note: Local Attestation 2.0 protocol will be used if 'LAv2' is defined.


When build is successful, you can find executable binaries in "bin" sub-folder.
 
------------------------------------
How to Execute the Sample Code
------------------------------------
1. Install SGX driver and PSW for Linux* OS
2. If you want to try local attestation flow from two process, you can goto "bin" sub-folder
   a. run "./appresponder".
      It would launch a process to act as local attestation responder.
   b. run "./appinitiator"
      It would launch a process to act as local attestation initator.
3. If you want to try local attestation flow from one process, you can goto "bin" sub-folder and run "./app"

------------------------------------
How to Get Signed Enclave's MRSIGNER
------------------------------------
1. Install Intel(R) Software Guard Extensions (Intel(R) SGX) SDK for Linux* OS
2. Execute blow command to get your signed enclave's MRSIGNER: 
    <SGX_SDK Installation Path>/bin/x64/sgx_sign dump -enclave <Signed Enclave> -dumpfile mrsigner.txt
3. Find the signed enclave's MRSIGNER in the mrsigner.txt(mrsigner->value:)
