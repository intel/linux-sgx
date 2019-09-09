# Reproducible Enclave Build
--------------------------------
Intel(R) SGX applications are built a trusted part and untrusted part. The SGX trusted part (Enclave) is protect by Intel® SGX technology. The signed enclave is running in the protected environment, it has the capability to access the sensitive secrets. So, user wants to confirm the enclave is built from the right source code with a clean tool chain. Sometimes, user would get a signed enclave from third party, user may want to confirm the enclave is the right one they should use. Below is a solution to help Intel(R) SGX user to achieve the goal by “reproduce the enclave build”.
In order to reproduce the enclave build, there are three requirements:1. stable source code 2. clean and secure environment and 3. auditable build tool chain. In this solution we use two opensource products: [Docker](https://www.docker.com/) and [Nix](https://nixos.org/) to achive the goal.

## Follow the below steps to setup the enclave build environment:
1. Install docker on the build machine:

Follow the [docker guide](https://docs.docker.com/install/).

2. Check out the SGX source code:
```
git clone https://github.com/intel/linux-sgx.git ~/linux-sgx
cd ~/linux-sgx
make dcap_source
./download_prebuilt.sh
```
3. Build docker image:
```
docker build -t sgx.build.env ~/linux-sgx/linux/docker
```
4. Launch the docker image:
```
docker run -v ~/linux-sgx:/linux-sgx -it --network none --rm sgx.build.env
```
5. Launch enclave build environment:
```
nix-shell ~/shell.nix
```
6. Build the sgx sdk installer:
```
cd /linux-sgx/sdk
make
/linux-sgx/linux/installer/bin/build-installpkg.sh sdk
```
7. Install the sdk installer:
```
/linux-sgx/linux/installer/bin/sgx_linux_x64_sdk_[version].bin
```
## Build the sample code enclave with SDK
```
cd [SGX SDK installed folder]
nix-shell ~/shell.nix
source environment
cd SampleCode/SampleEnclave
make enclave.signed.so
```
Copy the enclave.signed.so out of the docker.
