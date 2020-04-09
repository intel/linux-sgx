# Deploy SGX enclaves in containers

Files in this directory demonstrate how to build and deploy SGX enclave applications using the Intel(R) SGX SDK and PSW in docker containers.

## Quick Start

###  Prerequisites
1. Install [Docker and Compose](https://docs.docker.com/) and configure them properly following respective their installation guide.
2. Install [SGX out-of-tree driver](https://github.com/intel/linux-sgx-driver). **Note**: See below to run with the DCAP driver or an SGX capable kernel.

### Run with Docker Compose
This will start AESM and an SGX sample on one terminal using docker-compose.
```
$ ./build_compose_run.sh
```

### Run with Docker directly

Alternatively you can run AESM and SGX sample containers in two separate terminals.

In one terminal,
```
$ ./build_and_run_aesm_docker.sh
```
In another terminal,
```
$ ./build_and_run_sample_docker.sh
```

## Dockerfile

The [Dockerfile](../docker/Dockerfile)  specifies 3 image build targets:
1. sgxbase: Uses Ubuntu 18.04 base, adds SGX PPA repo hosted on 01.org to the package manager source list.
2. aesm: Installs sgx-aesm and its dependencies from the SGX PPA and starts the AESM service.
3. sample: Installs the SGX SDK and runtime libaries, builds and runs the SampleEnclave app in SDK sample code.

## DCAP driver and kernel with SGX patches

All SGX applications need access to the SGX device nodes exposed by kernel space driver. Depending on the driver or kernel you are using, the SGX device nodes may have different names and locations. Therefore, you need ensure those nodes mapped and mounted inside the containers appropriately.

[SGX kernel patches](https://github.com/jsakkine-intel/linux-sgx/commits/master) are still in process of upstreaming.
The [DCAP driver](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/driver) is developed to imitate the kernel patches as closely as possible. To use custom built kernel with SGX patches or the DCAP driver instead of the SGX2 driver mentioned above, you need make following modifications:
1. Replace "/dev/isgx" device with "/dev/sgx/enclave" and "/dev/sgx/provision" devices for AESM in docker-compose.yml  and build_and_run_aesm_docker.sh
2. Replace "/dev/isgx" with "/dev/sgx/enclave" for the sample container in docker-compose.yml and build_and_run_sample_docker.sh

**Note**: When you switch between the DCAP and SGX2 drivers, make sure you uninstall the previous driver and reset the OS before installing the other one.

**Note**: Earlier versions of the DCAP driver and kernel patches may expose the SGX device as a single node at "/dev/sgx".

