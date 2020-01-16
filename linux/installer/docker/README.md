# Deploy SGX enclaves in containers

Files in this directory demostrate how to deploy SGX enclave applications in docker containers.

## Quick Start

###  Prerequisites
1. Install [docker and composer](https://docs.docker.com/) and configure them properly following respective installation guide.
2. Install [SGX out-of-tree driver](https://github.com/intel/linux-sgx-driver). **Note**: See below to run with DCAP driver or SGX capable kernel.

### Run with docker composer
This will start aesm and sample from one terminal using docker composer.
```
$ ./build_compose_run.sh
```

### Run with docker directly

Alternative you can run aesm and sample containers in two separate terminals. 

In first terminal, 
```
$ ./build_and_run_aesm_docker.sh
```
In second terminal, 
```
$ ./build_and_run_sample_docker.sh
```


## Shell scripts
The shell scripts demostrate steps to build and start containers for different scenarios.
- [build_and_run_aesm_docker.sh](../docker/build_and_run_aesm_docker.sh) - build and run AESM in docker, using bin installer
- [build_and_run_sample_docker.sh](../docker/build_and_run_sample_docker.sh) - build and run SampleEnclave example in docker, using bin installer
- [build_compose_run.sh](../docker/build_compose_run.sh) - use docker composer to bring up separate containers for AESM and SampleEnclave example.

## The Dockerfile

The [Dockerfile](../docker/Dockerfile) is a multi-stage docker file that specifies 3 image build targets:
1. sgxbase: use ubuntu 18.04 base, add SGX PPA repo hosted on 01.org to package manager source list.
2. aesm: Install sgx-aesm and its dependencies from the SGX PPA, start AESM as service.
3. sample: Install SGX sdk and runtime libaries, build and run the SampleEnclave app in SDK sample code.

## DCAP driver and kernel with SGX patches

[SGX kernel patches](https://github.com/jsakkine-intel/linux-sgx/commits/master) are still in process of upstreaming.
The [DCAP driver](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/driver) is developed to imitate the kernel patches as closely as possible. To use custom built kernel with SGX patches or the DCAP driver instead of the SGX2 driver mentioned above, you need following modifications:
1. Replace "/dev/isgx" device with "/dev/sgx/enclave" and "/dev/sgx/provision" devices for aesm in docker-compose.yml  and build_and_run_aesm_docker.sh
2. Replace "/dev/isgx" with "/dev/sgx/enclave" for sample container in docker-compose.yml and build_and_run_sample_docker.sh 

**Note**: When you switch between DCAP driver, SGX2 driver, make sure you un-install previous driver and reset the OS before installing the other one.
