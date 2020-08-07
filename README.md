

Intel(R) Software Guard Extensions for Linux\* OS
================================================

# linux-sgx

Introduction
------------
Intel(R) Software Guard Extensions (Intel(R) SGX) is an Intel technology for application developers seeking to protect select code and data from disclosure or modification.

The Linux\* Intel(R) SGX software stack is comprised of the Intel(R) SGX driver, the Intel(R) SGX SDK, and the Intel(R) SGX Platform Software (PSW). The Intel(R) SGX SDK and Intel(R) SGX PSW are hosted in the [linux-sgx](https://github.com/01org/linux-sgx) project.

The [SGXDataCenterAttestationPrimitives](https://github.com/intel/SGXDataCenterAttestationPrimitives/) project maintains an out-of-tree driver for the Linux\* Intel(R) SGX software stack, which will be used until the driver upstreaming process is complete. It is used on the platforms with *Flexible Launch Control* and *Intel(R) AES New Instructions* support and could support both Elliptic Curve Digital Signature algorithm (ECDSA) based attestation and Enhanced Privacy Identification (EPID) based attestation.      
The [linux-sgx-driver](https://github.com/01org/linux-sgx-driver) project hosts the other out-of-tree driver for the Linux\* Intel(R) SGX software stack, which will be used until the driver upstreaming process is complete. It is used to support Enhanced Privacy Identification (EPID) based attestation on the platforms without *Flexible Launch Control*. 

The repository provides a reference implementation of a Launch Enclave for 'Flexible Launch Control' under [psw/ae/ref_le](psw/ae/ref_le). The reference LE implementation can be used as a basis for enforcing different launch control policy by the platform developer or owner. To build and try it by yourself, please refer to the [ref_le.md](psw/ae/ref_le/ref_le.md) for details.

License
-------
See [License.txt](License.txt) for details.

Contributing
-------
See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

Documentation
-------------
- [Intel(R) SGX for Linux\* OS](https://01.org/intel-softwareguard-extensions) project home page on [01.org](https://01.org)
- [Intel(R) SGX Programming Reference](https://software.intel.com/sites/default/files/managed/7c/f1/332831-sdm-vol-3d.pdf)

Quick Start with Docker and Docker Compose
-----------------------------------------

- Build PSW and SDK from source. See this [README](docker/build/README.md) for details.
```
$ cd docker/build && ./build_compose_run.sh
```

- Use prebuilt PSW and SDK downloaded from 01.org. See this [README](linux/installer/docker/README.md) for details.
```
$ cd linux/installer/docker && ./build_compose_run.sh
```
 
Build and Install the Intel(R) SGX Driver
-----------------------------------------
Follow the [README.md](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/driver/linux/README.md) in the [SGXDataCenterAttestationPrimitives](https://github.com/intel/SGXDataCenterAttestationPrimitives/) project to build and install the Intel(R) SGX driver.     
**NOTE**: The above Intel(R) SGX driver requires *Flexible Launch Control* and *Intel(R) AES New Instructions* support. If your platform doesn't meet the requirement, please follow  the instructions in the [linux-sgx-driver](https://github.com/01org/linux-sgx-driver) project to build and install this version of Intel(R) SGX driver.

Build the Intel(R) SGX SDK and Intel(R) SGX PSW Package
-------------------------------------------------------
### Prerequisites:
- Ensure that you have one of the following required operating systems:  
  * Ubuntu\* 16.04 LTS Desktop 64bits
  * Ubuntu\* 16.04 LTS Server 64bits
  * Ubuntu\* 18.04 LTS Desktop 64bits
  * Ubuntu\* 18.04 LTS Server 64bits
  * Red Hat Enterprise Linux Server release 7.6 64bits
  * Red Hat Enterprise Linux Server release 8.1 64bits
  * CentOS 8.1 64bits
  * Fedora 31 Server 64bits
  * SUSE Linux Enterprise Server 12 64bits

- Use the following command(s) to install the required tools to build the Intel(R) SGX SDK:  
  * On Ubuntu 16.04:
  ```
    $ sudo apt-get install build-essential ocaml automake autoconf libtool wget python libssl-dev git cmake perl
  ```
  * On Ubuntu 18.04:
  ```
    $ sudo apt-get install build-essential ocaml ocamlbuild automake autoconf libtool wget python libssl-dev git cmake perl
  ```
  * On Red Hat Enterprise Linux 7.6, Red Hat Enterprise Linux 8.1:
  ```
    $ sudo yum groupinstall 'Development Tools'
    $ sudo yum install ocaml ocaml-ocamlbuild wget python2 openssl-devel git cmake perl
    $ sudo alternatives --set python /usr/bin/python2
  ```
  * On CentOS 8.1:
  ```
    $ sudo dnf group install 'Development Tools'
    $ sudo dnf --enablerepo=PowerTools install ocaml ocaml-ocamlbuild redhat-rpm-config openssl-devel wget rpm-build git cmake perl python2
    $ sudo alternatives --set python /usr/bin/python2
  ```
  * On Fedora 31:
  ```
    $ sudo yum groupinstall 'C Development Tools and Libraries'
    $ sudo yum install ocaml ocaml-ocamlbuild redhat-rpm-config openssl-devel wget python rpm-build git cmake perl
  ```
  * On SUSE Linux Enterprise Server 12:
  ```
    $ sudo zypper install --type pattern devel_basis
    $ sudo zypper install ocaml ocaml-ocamlbuild automake autoconf libtool wget python libopenssl-devel rpm-build git cmake perl
  ```
   **Note**:  To build Intel(R) SGX SDK, gcc version is required to be 7.3 or above and glibc version is required to be 2.27 or above. For Ubuntu 16.04, Red Hat Enterprise Linux 7.6 and SUSE Linux Enterprise Server 12, you may need to update gcc and glibc version manually.
- Use the following command to install additional required tools and latest Intel(R) SGX SDK Installer to build the Intel(R) SGX PSW:  
  1)  To install the additional required tools:
      * On Ubuntu 16.04 and Ubuntu 18.04:
      ```
        $ sudo apt-get install libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper cmake reprepro unzip
      ```
      * On Red Hat Enterprise Linux 7.6, Red Hat Enterprise Linux 8.1 and Fedora 31:
      ```
        $ sudo yum install openssl-devel libcurl-devel protobuf-devel cmake rpm-build createrepo yum-utils
      ```
      * On CentOS 8.1:
      ```
        $ sudo dnf --enablerepo=PowerTools install openssl-devel libcurl-devel protobuf-devel cmake rpm-build createrepo yum-utils
      ```
      * On SUSE Linux Enterprise Server 12:
      ```
        $ sudo zypper install libopenssl-devel libcurl-devel protobuf-devel cmake rpm-build createrepo
      ```
  2) To install latest Intel(R) SGX SDK Installer
  Ensure that you have downloaded latest Intel(R) SGX SDK Installer from the [Intel(R) SGX SDK](https://software.intel.com/en-us/sgx-sdk/download) and followed the Installation Guide in the same page to install latest Intel(R) SGX SDK Installer.
  
- Use the script ``download_prebuilt.sh`` inside source code package to download prebuilt binaries to prebuilt folder  
  You may need set an https proxy for the `wget` tool used by the script (such as ``export https_proxy=http://test-proxy:test-port``)  
```
  $ ./download_prebuilt.sh
```

- Copy the mitigation tools corresponding to current OS distribution from external/toolset/{current_distr} to /usr/local/bin and make sure they have execute permission:
  ```
    $ sudo cp external/toolset/{current_distr}/{as,ld,ld.gold,objdump} /usr/local/bin
    $ which as ld ld.gold objdump
  ```
    **Note**: The above action is a must even if you copied the previous mitigation tools to /usr/local/bin before. It ensures the updated mitigation tools are used in the later build.


### Build the Intel(R) SGX SDK and Intel(R) SGX SDK Installer
- To build Intel(R) SGX SDK with default configuration, enter the following command:
```
  $ make sdk
```  
You can find the three flavors of tools and libraries generated in the `build` directory.

- This repository supports to build the Intel(R) SGX SDK with below three combinations:
  * `USE_OPT_LIBS=0` --- build SDK using SGXSSL and open sourced String/Math
  * `USE_OPT_LIBS=1` --- build SDK using optimized IPP crypto and open sourced String/Math
  The default build uses `USE_OPT_LIBS=1`, if you directly type `$ make sdk` as above.
  You can switch to the other build combination instead by entering the following command:
```
  $ make sdk USE_OPT_LIBS=0
```
  **Note**: Building the Intel(R) SGX PSW with open sourced SGXSSL/string/math libraries is not supported. 

- To build Intel(R) SGX SDK with debug information, enter the following command:
```
  $ make sdk DEBUG=1
```

- To clean the files generated by previous `make sdk` command, enter the following command:  
```
  $ make clean
```
- To build the Intel(R) SGX SDK installer, enter the following command:
```
  $ make sdk_install_pkg
```
You can find the generated Intel(R) SGX SDK installer ``sgx_linux_x64_sdk_${version}.bin`` located under `linux/installer/bin/`, where `${version}` refers to the version number.

**Note**: The above command builds the Intel(R) SGX SDK with default configuration firstly and then generates the target SDK Installer. To build the Intel(R) SGX SDK Installer with debug information kept in the tools and libraries, enter the following command:
```
  $ make sdk_install_pkg DEBUG=1
```

### Build the Intel(R) SGX PSW and Intel(R) SGX PSW Installer
- To build Intel(R) SGX PSW with default configuration, enter the following command:
```
  $ make psw
```
You can find the tools and libraries generated in the `build/linux` directory.
  **Note**: You can also go to the `psw` folder and use the `make` command to build the Intel(R) SGX PSW component only.  
- To build Intel(R) SGX PSW with debug information, enter the following command:
```
  $ make psw DEBUG=1
```
- To clean the files generated by previous `make psw` command, enter the following command:  
```
  $ make clean
```
- The build above uses prebuilt Intel(R) Architecture Enclaves(LE/PvE/QE/PCE) - the files ``psw/ae/data/prebuilt/libsgx_*.signed.so``, which have been signed by Intel in advance.
  To build those enclaves by yourself (without a signature), first you need to install latest Intel(R) SGX SDK from the [Intel(R) SGX SDK](https://software.intel.com/en-us/sgx-sdk/download) and then build PSW with the default configuration. After that, you can build each Architecture Enclave by using the `make` command from the corresponding folder:
```
  $ cd psw/ae/le
  $ make
``` 
- To build the Intel(R) SGX PSW installer, enter the following command:
  * On Ubuntu 16.04 and Ubuntu 18.04:
   ```
  $ make deb_psw_pkg
  ```
  You can find the generated Intel(R) SGX PSW installers located under `linux/installer/deb/libsgx-urts`, `linux/installer/deb/libsgx-enclave-common`, `linux/installer/deb/libsgx-uae-service`, `linux/installer/deb/libsgx-epid`, `linux/installer/deb/libsgx-launch`, `linux/installer/deb/libsgx-quote-ex` and `linux/installer/deb/sgx-aesm-service` respectively.

  **Note**: On Ubuntu 18.04, besides the Intel(R) SGX PSW installer, the above command generates another debug symbol package named ``package-name-dbgsym_${version}-${revision}_amd64.ddeb`` for debug purpose. On Ubuntu 16.04, if you want to keep debug symbols in the Intel(R) SGX PSW installer, before building the Intel(R) SGX PSW, you need to export an environment variable to ensure the debug symbols not stripped:
   ```
   $ export DEB_BUILD_OPTIONS="nostrip"
   ```
  **Note**: Starting with the 2.10 release, besides the Intel(R) SGX PSW installer, the above command generates [SGXDataCenterAttestationPrimitives](https://github.com/intel/SGXDataCenterAttestationPrimitives/) installers on OS newer than Ubuntu 16.04. Ubuntu 16.04 is not included because of GCC version.

  **Note**: The above command builds the Intel(R) SGX PSW with default configuration firstly and then generates the target PSW Installer. To build the Intel(R) SGX PSW Installer without optimization and with full debug information kept in the tools and libraries, enter the following command:
  ```
  $ make deb_psw_pkg DEBUG=1
  ```
  * On Red Hat Enterprise Linux 7.6, Red Hat Enterprise Linux 8.1, CentOS 8.1, Fedora 31 and SUSE Linux Enterprise Server 12:
  ```
  $ make rpm_psw_pkg
  ```
  You can find the generated Intel(R) SGX PSW installers located under `linux/installer/rpm/libsgx-urts`, `linux/installer/rpm/libsgx-enclave-common`, `linux/installer/rpm/libsgx-uae-service`, `linux/installer/rpm/libsgx-epid`, `linux/installer/rpm/libsgx-launch`, `linux/installer/rpm/libsgx-quote-ex` and `linux/installer/rpm/sgx-aesm-service` respectively.

  **Note**: The above command builds the Intel(R) SGX PSW with default configuration firstly and then generates the target PSW Installer. To build the Intel(R) SGX PSW Installer with debug information kept in the tools and libraries, enter the following command:
  ```
  $ make rpm_psw_pkg DEBUG=1
  ```

  - To build local Debian package repository, enter the following command:
  ```
  $ make deb_local_repo
  ```
  You can find the local package repository located under `linux/installer/deb/sgx_debian_local_repo`.
  
    **Note**: The above command builds the local package repository. If you want to use it, you need to add it to the system repository configuration. The local package repository is not signed, you need to trust it for the purpose of development.

  - To add the local Debian package repository to the system repository configuration, append the following line to /etc/apt/sources.list. You need to replace PATH_TO_LOCAL_REPO with the proper path on your system:
  
  * On Ubuntu 16.04:
  ```
  deb [trusted=yes arch=amd64] file:/PATH_TO_LOCAL_REPO xenial main
  ```
  * On Ubuntu 18.04:
  ```
  deb [trusted=yes arch=amd64] file:/PATH_TO_LOCAL_REPO bionic main
  ```
  After that, you need to update the apt:
  * On Ubuntu 16.04 and Ubuntu 18.04:
  ```
  $ sudo apt update
  ```

  - To build local RPM package repository, enter the following command:
  ```
  $ make rpm_local_repo
  ```
  You can find the local package repository located under `linux/installer/rpm/sgx_rpm_local_repo`.
  
  **Note**: The above command builds the local package repository. If you want to use it, you need to add it to the system repository configuration. Since the local package repository is not signed with GPG, you should ignore the gpgcheck when installing the packages.

  - To add the local RPM package repository to the system repository configuration, you can use the following command. You need to replace PATH_TO_LOCAL_REPO with the proper path on your system:
  * On Red Hat Enterprise Linux 7.6, Red Hat Enterprise Linux 8.1, CentOS 8.1, Fedora 31:
  ```
  $ sudo yum-config-manager --add-repo file://PATH_TO_LOCAL_REPO
  ```
  * On SUSE Linux Enterprise Server 12, you need to replace LOCAL_REPO_ALIAS with proper alias name for the local repo:
  ```
  $ sudo zypper addrepo PATH_TO_LOCAL_REPO LOCAL_REPO_ALIAS
  ```
  - To ignore the gpgcheck when you install the package, enter the following command:
  * On Red Hat Enterprise Linux 7.6, Red Hat Enterprise Linux 8.1, CentOS 8.1, Fedora 31:
  ```
  $ sudo yum --nogpgcheck install <package>
  ```
  * On SUSE Linux Enterprise Server 12:
  ```
  $ sudo zypper --no-gpg-checks install <package>
  ```

Install the Intel(R) SGX SDK
------------------------
### Prerequisites
- Ensure that you have one of the following operating systems:  
  * Ubuntu\* 16.04 LTS Desktop 64bits
  * Ubuntu\* 16.04 LTS Server 64bits
  * Ubuntu\* 18.04 LTS Desktop 64bits
  * Ubuntu\* 18.04 LTS Server 64bits
  * Red Hat Enterprise Linux Server release 7.6 64bits
  * Red Hat Enterprise Linux Server release 8.1 64bits
  * CentOS 8.1 64bits
  * Fedora 31 Server 64bits
  * SUSE Linux Enterprise Server 12 64bits
- Use the following command to install the required tool to use Intel(R) SGX SDK:
  * On Ubuntu 16.04 and Ubuntu 18.04:
  ```  
    $ sudo apt-get install build-essential python
  ```
  * On Red Hat Enterprise Linux 7.6, Red Hat Enterprise Linux 8.1 and CentOS 8.1:
  ```
     $ sudo yum groupinstall 'Development Tools'
     $ sudo yum install python2
     $ sudo alternatives --set python /usr/bin/python2 
  ```
  * On Fedora 31:
  ```
     $ sudo yum groupinstall 'C Development Tools and Libraries'
  ```
  * On SUSE Linux Enterprise Server 12:
  ```
     $ sudo zypper install --type pattern devel_basis
     $ sudo zypper install python 
  ```

### Install the Intel(R) SGX SDK
To install the Intel(R) SGX SDK, invoke the installer, as follows:
```
$ cd linux/installer/bin
$ ./sgx_linux_x64_sdk_${version}.bin
```
NOTE: You need to set up the needed environment variables before compiling your code. To do so, run:
```
  $ source ${sgx-sdk-install-path}/environment
```

### Test the Intel(R) SGX SDK Package with the Code Samples
- Compile and run each code sample in Simulation mode to make sure the package works well:    
```
  $ cd SampleCode/LocalAttestation
  $ make SGX_MODE=SIM
  $ cd bin
  $ ./app
```
   Use similar commands for other sample codes.

### Compile and Run the Code Samples in the Hardware Mode
If you use an Intel SGX hardware enabled machine, you can run the code samples in Hardware mode.
Ensure that you install Intel(R) SGX driver and Intel(R) SGX PSW installer on the machine.  
See the earlier topic, *Build and Install the Intel(R) SGX Driver*, for information on how to install the Intel(R) SGX driver.  
See the later topic, *Install Intel(R) SGX PSW*, for information on how to install the PSW package.
- Compile and run each code sample in Hardware mode, Debug build, as follows:  
```
  $ cd SampleCode/LocalAttestation
  $ make
  $ cd bin
  $ ./app
```
   Use similar commands for other code samples.


Install the Intel(R) SGX PSW
----------------------------
### Prerequisites
- Ensure that you have one of the following operating systems:  
  * Ubuntu\* 16.04 LTS Desktop 64bits
  * Ubuntu\* 16.04 LTS Server 64bits
  * Ubuntu\* 18.04 LTS Desktop 64bits
  * Ubuntu\* 18.04 LTS Server 64bits
  * Red Hat Enterprise Linux Server release 7.6 64bits
  * Red Hat Enterprise Linux Server release 8.1 64bits
  * CentOS 8.1 64bits
  * Fedora 31 Server 64bits
  * SUSE Linux Enterprise Server 12 64bits
- Ensure that you have a system with the following required hardware:  
  * 6th Generation Intel(R) Core(TM) Processor or newer
- Configure the system with the **Intel SGX hardware enabled** option and install Intel(R) SGX driver in advance.  
  See the earlier topic, *Build and Install the Intel(R) SGX Driver*, for information on how to install the Intel(R) SGX driver.
- Install the library using the following command:  
  * On Ubuntu 16.04 and Ubuntu 18.04:
  ```
    $ sudo apt-get install libssl-dev libcurl4-openssl-dev libprotobuf-dev
  ```
  * On Red Hat Enterprise Linux 7.6, Red Hat Enterprise Linux 8.1 and Fedora 31:  
  ```
    $ sudo yum install openssl-devel libcurl-devel protobuf-devel
  ```
  * On CentOS 8.1:
  ```
    $ sudo dnf --enablerepo=PowerTools install libcurl-devel protobuf-devel
  ```
  * On SUSE Linux Enterprise Server 12:  
  ```
    $ sudo zypper install libopenssl-devel libcurl-devel protobuf-devel
  ```

### Install the Intel(R) SGX PSW
- The SGX PSW provides 3 services: launch, EPID-based attestation, and algorithm agnostic attestation. Starting with the 2.8 release, the SGX PSW is split into smaller packages and the user can choose which features and services to install. There are 2 methods to install the required packages: Using individual packages or using the local repo generated by the build system. Using the local repo is recommended since the system will resolve the dependencies automatically. Currently, we support .deb and .rpm based repos. 

  #### Using the local repo(recommended)

  |   |Ubuntu 16.04, Ubuntu 18.04|Red Hat Enterprise Linux 7.6, Red Hat Enterprise Linux 8.1, CentOS 8.1, Fedora 31|SUSE Linux Enterprise Server 12|
  | ------------ | ------------ | ------------ | ------------ |
  |launch service |apt-get install libsgx-launch libsgx-urts|yum install libsgx-launch libsgx-urts|zypper install libsgx-launch libsgx-urts|
  |EPID-based attestation service|apt-get install libsgx-epid libsgx-urts|yum install libsgx-epid libsgx-urts|zypper install libsgx-epid libsgx-urts||
  |algorithm agnostic attestation service|apt-get install libsgx-quote-ex libsgx-urts|yum install libsgx-quote-ex libsgx-urts|zypper install libsgx-quote-ex libsgx-urts|
  |DCAP ECDSA-based service(Ubuntu16.04 not included)|apt-get install libsgx-dcap-ql|yum install libsgx-dcap-ql|zypper install libsgx-dcap-ql|

  Optionally, you can install *-dbgsym or *-debuginfo packages to get the debug symbols, and install *-dev or *-devel packages to get the header files for development.

  **NOTE**: To debug with sgx-gdb on Ubuntu 16.04, you need to ensure the Intel(R) SGX PSW is built under the condition that the environment variable ``DEB_BUILD_OPTIONS="nostrip"`` is set. 

  #### Using the individual packages
  Please refer [Intel_SGX_Installation_Guide_Linux](https://download.01.org/intel-sgx/latest/linux-latest/docs/) for detail.

  #### Upgrade from a legacy installation
  Before release 2.8, SGX PSW is installed as a single package named as libsgx-enclave-common. Starting with the 2.8 release, SGX PSW is split into smaller packages. libsgx-enclave-common is one of them. As a result, a simple upgrade will end up with a subset of the SGX PSW being installed on the system. You need to install additional packages to enable the required feature. At the same time, you will encounter some error message when you try to upgrade to release 2.8 from an old installation. You can use 2 methods to address it.
  * Uninstall the old installation first, then install new packages.
  * Add ``-o Dpkg::Options::="--force-overwrite"`` option to overwrite existing files and use “``dist-upgrade``” instead of "upgrade" to install new packages when upgrading. In short, you should use this command:
  ```
  apt-get dist-upgrade -o Dpkg::Options::="--force-overwrite"
  ```
  #### Configure the installation
  Some packages are configured with recommended dependency on other packages that are not required for certain usage. For instance, the background daemon is not required for container usage. It will be installed by default, but you can drop it by using the additional option during the installation.
  * On Ubuntu 16.04, Ubuntu 18.04:
  ```
    --no-install-recommends
  ```
  **NOTE** On rpm based system, rpmbuild>=4.12 is required to enable similar features. 

### ECDSA attestation
To enable ECDSA attestation    
- Ensure that you have the following required hardware:
  * 8th Generation Intel(R) Core(TM) Processor or newer with **Flexible Launch Control** support*
  * Intel(R) Atom(TM) Processor with **Flexible Launch Control** support*
- To use ECDSA attestation, you must install Intel(R) Software Guard Extensions Driver for Data Center Attestation Primitives (Intel(R) SGX DCAP).
Please follow the [Intel(R) SGX DCAP Installation Guide for Linux* OS](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_DCAP_Linux_SW_Installation_Guide.pdf) to install the Intel(R) SGX DCAP driver.

**NOTE**: If you had already installed Intel(R) SGX driver without ECDSA attestation, please uninstall the driver firstly and then install the Intel(R) SGX DCAP driver. Otherwise the newly installed Intel(R) SGX DCAP driver will be unworkable.

- Install Quote Provider Library(QPL). You can use your own customized QPL or use default QPL provided by Intel(libsgx-dcap-default-qpl)

- Install PCK Caching Service. For how to install and configure PCK Caching
Service, please refer to [SGXDataCenterAttestationPrimitives](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/QuoteGeneration/pccs)
- Ensure the PCK Caching Service is setup correctly by local administrator or data center administrator. Also make sure that the configure file of quote provider library (/etc/sgx_default_qcnl.conf) is consistent with the real environment, for example: PCS_URL=https://your_pcs_server:8081/sgx/certification/v1/

### Start or Stop aesmd Service
The Intel(R) SGX PSW installer installs an aesmd service in your machine, which is running in a special linux account `aesmd`.  
To stop the service: `$ sudo service aesmd stop`  
To start the service: `$ sudo service aesmd start`  
To restart the service: `$ sudo service aesmd restart`

### Configure the Proxy for aesmd Service
The aesmd service uses the HTTP protocol to initialize some services.  
If a proxy is required for the HTTP protocol, you may need to manually set up the proxy for the aesmd service.  
You should manually edit the file `/etc/aesmd.conf` (refer to the comments in the file) to set the proxy for the aesmd service.  
After you configure the proxy, you need to restart the service to enable the proxy.

Reproducibility
-----------------------------------------
Intel(R) SGX is providing several prebuilt binaries. All the prebuilt binaries are built from a reproducible environment in SGX docker container. To reproduce the prebuilt binaries, please follow the [reproducibility README.md](linux/reproducibility/README.md) to prepare the SGX docker container and build out the binaries you want to verify.
Most of the binaries could be verified utilizing Linux system command `diff`, except Intel(R) AEs. Please refer to the [README.md](linux/reproducibility/ae_reproducibility_verifier/README.md) for how to verify the reproducibililty of the built out AEs.
