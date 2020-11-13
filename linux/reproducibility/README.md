# Reproducible Enclave Build
--------------------------------
Intel(R) SGX applications are built a trusted part and untrusted part. The SGX trusted part (Enclave) is protect by Intel® SGX technology. The signed enclave is running in the protected environment, it has the capability to access the sensitive secrets. So, user wants to confirm the enclave is built from the right source code with a clean tool chain. Sometimes, user would get a signed enclave from third party, user may want to confirm the enclave is the right one they should use. Below is a solution to help Intel(R) SGX user to achieve the goal by “reproduce the enclave build”.
In order to reproduce the enclave build, there are three requirements:1. stable source code 2. clean and secure environment and 3. auditable build tool chain. In this solution we use two opensource products: [Docker](https://www.docker.com/) and [Nix](https://nixos.org/) to achieve the goal.


## Files
--------
 - The [Dockerfile](./Dockerfile) is provided to build a docker image with NIX environment for reproducible build.
 - The script [build_and_launch_docker.sh](./build_and_launch_docker.sh) is the interface to automate the reproducibility process for Intel(R) SGX. You can directly run this script in the host machine to verify the reproducibility. Currently below five reproducible types are supported:   
    * sdk: specify this type if you want to verify the reproducibility for Intel(R) SGX SDK. The script will prepare the SDK code in the host machine and trigger SDK build in the launched container.      
    * ipp: specify this type if you want to verify the reproducibility for the prebuilt IPP crypto. The script will prepare the IPP crypto code in the host machine and trigger the build in the launched container.    
    * binutils: specify this type if you want to verify the reproducibilty for the prebuilt binutils. Th script will prepare the binutils code in the host machine and trigger the corresponding build in the launched container.       
    * ae:  specify this type if you want to verify the reproducibilty for the prebuilt AEs. The script will prepare materials for AE repredocible build in the hose machine and trigger the corresponding build in the launched container.    
    * all: specify this type if you want to verify all of the above components. The script will prepare materials for all the targets and trigger  the build in the launched container.   
 See `$ ./build_and_launch_docker.sh -h` for details  
 - The script [start_build.sh.tmp](./start_build.sh.tmp) is aimed to be run in the NIX environment in the launched container. It helps to automate the reproducible build in the container.


## Quick Start
---------------
- Install docker and configure them correctly on the build machine following the [docker guide](https://docs.docker.com/install/).

- Run the provided script [build_and_launch_docker.sh](./build_and_launch_docker.sh) to prepare the reproducible build environment and automate the build in the container.    
  * Examples:    
    a) Below command triggers the reproducible build for 'all' of the reproducible components. The built out materials could be found under `~/code_dir/out/`
    ```
    $ ./build_and_launch_docker.sh --reproduce-type all --code-dir ~/code_dir
    ```
    b) Below command prepares the code, build the docker image and launch the container after that. It doesn't trigger any build in the container.
    ```
    $ ./build_and_launch_docker.sh
    ```
    c) Below command triggers the reproducible build for 'ae' using a specified reproducible SGX SDK installer and code repo. Of course, you need to prepare the SGX SDK installer and SGX source repo beforehand.
    ```
    $ ./build_and_launch_docker.sh --reproduce-type ae --code-dir ~/code_dir --sdk-installer {prepared_sdk_installer} --sgx-src-dir {prepared_sgx_src}
    ```


**Note**:
To reproduce QVE, you need to apply below patch to the [build_and_launch_docker.sh](./build_and_launch_docker.sh) before start the reproducible build with the script.
```
diff --git a/linux/reproducibility/build_and_launch_docker.sh b/linux/reproducibility/build_and_launch_docker.sh
index 2b3ea886..eb7e4086 100755
--- a/linux/reproducibility/build_and_launch_docker.sh
+++ b/linux/reproducibility/build_and_launch_docker.sh
@@ -183,6 +183,7 @@ prepare_sgx_src()
     fi

     cd "$sgx_repo" && make preparation
+    mkdir dcap-trunk/ && mv external/dcap_source/ dcap-trunk/  && ln -sfr dcap-trunk/dcap_source external/dcap_source
     popd

 }
```


