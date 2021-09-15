# Deploy SGX enclaves in containers

Files in this directory demonstrate how to build and deploy SGX enclave applications using the Intel(R) SGX SDK and PSW in docker containers.

## Quick Start

###  Prerequisites
1. Install [Docker and Compose](https://docs.docker.com/) and configure them properly following respective their installation guide.
2. Install [SGX Flexible Launch Control driver](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/driver/linux). **Note**: See below to run with the Legacy Launch Control driver.

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

## Legacy Launch Control driver and kernel for SGX

All SGX applications need access to the SGX device nodes exposed by the kernel space driver. Depending on the driver or kernel you are using, the SGX device nodes may have different names and locations. Therefore, you need to ensure those nodes are mapped and mounted inside the containers properly.


[SGX kernel patches](https://github.com/jsakkine-intel/linux-sgx/commits/master) are still in process of upstreaming.
The [Flexible Launch Control driver](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/driver) is developed to imitate the kernel patches as closely as possible.

The sample scripts and Compose files are compatible with the Flexible Launch Control  driver or a custom built kernel with SGX support. If you need to use the Legacy Launch Control driver then you need to make following modifications:
1. Replace "/dev/sgx/enclave" device with "/dev/isgx" and **remove** "/dev/sgx/provision" device for AESM in docker-compose.yml and build_and_run_aesm_docker.sh
2. Replace "/dev/sgx/enclave" with "/dev/isgx" for the sample container in docker-compose.yml and build_and_run_sample_docker.sh

**Note**: When you switch between drivers, make sure you uninstall the previous driver and reboot the system before installing the other one.

**Note**: Earlier versions of the Flexible Launch Control driver and kernel patches may expose the SGX device as a single node at "/dev/sgx".

