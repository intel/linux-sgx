---------------------------
The project aims to demo SGX local attestation flow. 

------------------------------------
How to Build the Sample Code
------------------------------------
1. Install Intel(R) Software Guard Extensions (Intel(R) SGX) SDK for Linux* OS
2. Build the project with the prepared Makefile:
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
