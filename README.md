

Intel(R) Software Guard Extensions for Linux\* OS
================================================

# linux-sgx
* [Introduction](#introduction)
* [License](#license)
* [Contributing](#contributing)
* [Documentation](#documentation)
* [Quick Start with Docker and Docker Compose](#quick-start-with-docker-and-docker-compose)
* [Build and Install the Intel(R) SGX Driver](#build-and-install-the-intelr-sgx-driver)
* [Build the Intel(R) SGX SDK and Intel(R) SGX PSW Package](#build-the-intelr-sgx-sdk-and-intelr-sgx-psw-package)
    * [Prerequisites](#prerequisites)
    * [Build the Intel(R) SGX SDK and Intel(R) SGX SDK Installer](#build-the-intelr-sgx-sdk-and-intelr-sgx-sdk-installer)
    * [Build the Intel(R) SGX PSW and Intel(R) SGX PSW Installer](#build-the-intelr-sgx-psw-and-intelr-sgx-psw-installer)
* [Install the Intel(R) SGX SDK](#install-the-intelr-sgx-sdk)
    * [Prerequisites](#prerequisites-1)
    * [Install the Intel(R) SGX SDK](#install-the-intelr-sgx-sdk-1)
    * [Test the Intel(R) SGX SDK Package with the Code Samples](#test-the-intelr-sgx-sdk-package-with-the-code-samples)
    * [Compile and Run the Code Samples in the Hardware Mode](#compile-and-run-the-code-samples-in-the-hardware-mode)
* [Install the Intel(R) SGX PSW](#install-the-intelr-sgx-psw)
    * [Prerequisites](#prerequisites-2)
    * [Install the Intel(R) SGX PSW](#install-the-intelr-sgx-psw-1)
        * [Using the local repo(recommended)](#using-the-local-reporecommended)
        * [Using the individual packages](#using-the-individual-packages)
        * [Upgrade from a legacy installation](#upgrade-from-a-legacy-installation)
        * [Configure the installation](#configure-the-installation)
    * [ECDSA attestation](#ecdsa-attestation)
    * [Start or Stop aesmd Service](#start-or-stop-aesmd-service)
    * [Configure the Proxy for aesmd Service](#configure-the-proxy-for-aesmd-service)
* [Reproducibility](#reproducibility)


Introduction
------------
Intel(R) Software Guard Extensions (Intel(R) SGX) is an Intel technology for application developers seeking to protect select code and data from disclosure or modification.

The Linux\* Intel(R) SGX software stack is comprised of the Intel(R) SGX driver, the Intel(R) SGX SDK, and the Intel(R) SGX Platform Software (PSW). The Intel(R) SGX SDK and Intel(R) SGX PSW are hosted in the [linux-sgx](https://github.com/intel/linux-sgx) project.

The [SGXDataCenterAttestationPrimitives](https://github.com/intel/SGXDataCenterAttestationPrimitives/) project maintains an out-of-tree driver for the Linux\* Intel(R) SGX software stack, which will be used until the driver upstreaming process is complete. It is used on the platforms with *Flexible Launch Control* and *Intel(R) AES New Instructions* support and could support both Elliptic Curve Digital Signature algorithm (ECDSA) based attestation and Enhanced Privacy Identification (EPID) based attestation.

**Note**: Ice Lake Xeon-SP (and the future Xeon-SP platforms) doesn't support EPID attestation.

The [linux-sgx-driver](https://github.com/intel/linux-sgx-driver) project hosts the other out-of-tree driver for the Linux\* Intel(R) SGX software stack, which will be used until the driver upstreaming process is complete. It is used to support Enhanced Privacy Identification (EPID) based attestation on the platforms without *Flexible Launch Control*.

The [intel-device-plugins-for-kubernetes](https://github.com/intel/intel-device-plugins-for-kubernetes) project enables users to run container applications running Intel(R) SGX enclaves in Kubernetes clusters. It also gives instructions how to set up ECDSA based attestation in a cluster.


The [intel-sgx-ssl](https://github.com/intel/intel-sgx-ssl) project provides a full-strength general purpose cryptography library for Intel(R) SGX enclave applications. It is based on the underlying OpenSSL* Open Source project. Intel(R) SGX provides a build combination to build out a SGXSSL based SDK as [below](#build-the-intelr-sgx-sdk-and-intelr-sgx-sdk-installer). Users could also utilize this cryptography library in SGX enclave applications seperately.


This repository provides a reference implementation of a Launch Enclave for 'Flexible Launch Control' under [psw/ae/ref_le](psw/ae/ref_le). The reference LE implementation can be used as a basis for enforcing different launch control policy by the platform developer or owner. To build and try it by yourself, please refer to the [ref_le.md](psw/ae/ref_le/ref_le.md) for details.
**NOTE**: The reference LE is only workable with [linux-sgx-driver](https://github.com/intel/linux-sgx-driver) and is planned to be deprecated starting from Intel(R) SGX release 2.20.

License
-------
See [License.txt](License.txt) for details.

Contributing
-------
See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

Documentation
-------------
- [Intel(R) SGX for Linux\* OS](https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/linux-overview.html) project home page on [Intel Developer Zone](https://www.intel.com/content/www/us/en/developer/overview.html)
- [Intel(R) SGX Programming Reference](https://www.intel.com/content/dam/develop/external/us/en/documents/329298-002-629101.pdf)

Quick Start with Docker and Docker Compose
-----------------------------------------

- Build PSW and SDK from source. See this [README](docker/build/README.md) for details.
```
$ cd docker/build && ./build_compose_run.sh
```

- Build and deploy SGX exclave applications using prebuilt PSW and SDK downloaded from 01.org. See this [README](linux/installer/docker/README.md) for details.
```
$ cd linux/installer/docker && ./build_compose_run.sh
```

Build and Install the Intel(R) SGX Driver
-----------------------------------------
Follow the [README.md](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/driver/linux/README.md) in the [SGXDataCenterAttestationPrimitives](https://github.com/intel/SGXDataCenterAttestationPrimitives/) project to build and install the Intel(R) SGX driver.
**NOTE**: The above Intel(R) SGX driver requires *Flexible Launch Control* and *Intel(R) AES New Instructions* support. If your platform doesn't meet the requirement, please follow  the instructions in the [linux-sgx-driver](https://github.com/intel/linux-sgx-driver) project to build and install this version of Intel(R) SGX driver.

Build the Intel(R) SGX SDK and Intel(R) SGX PSW Package
-------------------------------------------------------
### Prerequisites:
- Ensure that you have one of the following required operating systems:
  * Ubuntu\* 20.04 LTS Desktop 64bits
  * Ubuntu\* 20.04 LTS Server 64bits
  * Ubuntu\* 22.04 LTS Server 64bits
  * Ubuntu\* 24.04 LTS Server 64bits
  * Red Hat Enterprise Linux Server release 9.2 64bits
  * CentOS Stream 9 64bits
  * CentOS 8.3 64bits
  * SUSE Linux Enterprise Server 15.4 64bits
  * Anolis OS 8.6 64bits
  * Debian 10 64bits

- Use the following command(s) to install the required tools to build the Intel(R) SGX SDK:
  * On Debian 10:
  ```
    $ sudo apt-get install build-essential ocaml ocamlbuild automake autoconf libtool wget python3 libssl-dev git cmake perl
    $ sudo update-alternatives --install /usr/bin/python python /usr/bin/python3 1
  ```
  * On Ubuntu 20.04, Ubuntu 22.04 and Ubuntu 24.04:
  ```
    $ sudo apt-get install build-essential ocaml ocamlbuild automake autoconf libtool wget python-is-python3 libssl-dev git cmake perl
  ```
  * On Red Hat Enterprise Linux 9.2:
  ```
    $ sudo yum groupinstall 'Development Tools'
    $ sudo yum install ocaml ocaml-ocamlbuild wget python3 openssl-devel git cmake perl
  ```
  * On CentOS Stream 9:
  ```
    $ sudo dnf group install 'Development Tools'
    $ sudo dnf install ocaml ocaml-ocamlbuild redhat-rpm-config openssl-devel wget rpm-build git cmake perl python3
  ```  
  * On CentOS 8.3:
  ```
    $ sudo dnf group install 'Development Tools'
    $ sudo dnf --enablerepo=powertools install ocaml ocaml-ocamlbuild redhat-rpm-config openssl-devel wget rpm-build git cmake perl python3
    $ sudo alternatives --set python /usr/bin/python3
  ```
  * On Anolis 8.6:
  ```
    $ sudo dnf group install 'Development Tools'
    $ sudo dnf --enablerepo=PowerTools install ocaml ocaml-ocamlbuild redhat-rpm-config openssl-devel wget rpm-build git cmake perl python3
    $ sudo alternatives --set python /usr/bin/python3
  ```
  * On SUSE Linux Enterprise Server 15.4:
  ```
    $ sudo zypper install --type pattern devel_basis
    $ sudo zypper install ocaml ocaml-ocamlbuild automake autoconf libtool wget python3 libopenssl-devel rpm-build git cmake perl
    $ sudo update-alternatives --install /usr/bin/python python /usr/bin/python3 1
  ```
   **Note**:  To build Intel(R) SGX SDK, gcc version is required to be 7.3 or above and glibc version is required to be 2.27 or above.
- Use the following command to install additional required tools and latest Intel(R) SGX SDK Installer to build the Intel(R) SGX PSW:
  1)  To install the additional required tools:
      * On Debian 10:
      ```
        $ sudo apt-get install libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper cmake reprepro unzip  pkgconf libboost-dev libboost-system-dev libboost-thread-dev lsb-release libsystemd0
      ```
      * On Ubuntu 20.04, Ubuntu 22.04 and Ubuntu 24.04:
      ```
        $ sudo apt-get install libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper cmake reprepro unzip pkgconf libboost-dev libboost-system-dev libboost-thread-dev lsb-release libsystemd0
      ```
      * On Red Hat Enterprise Linux 9.2:
      ```
        $ sudo yum install openssl-devel libcurl-devel protobuf-devel cmake rpm-build createrepo yum-utils pkgconf boost-devel protobuf-lite-devel systemd-libs
      ```
      * On CentOS Stream 9:
      ```
        $ sudo dnf install openssl-devel libcurl-devel protobuf-devel cmake rpm-build createrepo yum-utils pkgconf boost-devel protobuf-lite-devel systemd-libs
      ```      
      * On CentOS 8.3:
      ```
        $ sudo dnf --enablerepo=powertools install openssl-devel libcurl-devel protobuf-devel cmake rpm-build createrepo yum-utils pkgconf boost-devel protobuf-lite-devel systemd-libs
      ```
      * On Anolis 8.6:
      ```
        $ sudo dnf --enablerepo=PowerTools install openssl-devel libcurl-devel protobuf-devel cmake rpm-build createrepo yum-utils pkgconf boost-devel protobuf-lite-devel systemd-libs
      ```
      * On SUSE Linux Enterprise Server 15.4:
      ```
        $ sudo zypper install libopenssl-devel libcurl-devel protobuf-devel cmake rpm-build createrepo_c libsystemd0 libboost_system1_66_0-devel libboost_thread1_66_0-devel
      ```
      2) To install latest Intel(R) SGX SDK Installer
  Ensure that you have downloaded latest Intel(R) SGX SDK Installer from the [Intel(R) SGX SDK](https://software.intel.com/en-us/sgx-sdk/download) and followed the Installation Guide in the same page to install latest Intel(R) SGX SDK Installer.

- Download the source code and prepare the submodules and prebuilt binaries:
```
   $ git clone https://github.com/intel/linux-sgx.git
   $ cd linux-sgx && make preparation
```
  The above ``make preparation`` would trigger the script ``download_prebuilt.sh`` to download the prebuilt binaries. You may need to set an https proxy for the `wget` tool used by the script (such as ``export https_proxy=http://test-proxy:test-port``)

- (*Optional*) If the binutils on your current operating system distribution doesn't support mitigation options, copy the mitigation tools corresponding to current OS distribution from external/toolset/{current_distr} to /usr/local/bin and make sure they have execute permission:
  ```
    $ sudo cp external/toolset/{current_distr}/* /usr/local/bin
    $ which ar as ld objcopy objdump ranlib
  ```
    **Note**: Mitigation tools are only provided for the operating systems whose binutils lack mitigation options support. If your operating system is not listed in the external/toolset/{current_distr} directory, you can skip this step. Otherwise, even if you previously copied the mitigation tools to /usr/local/bin, performing the above action is still necessary. This ensures that the latest mitigation tools are used during the subsequent build process.


### Build the Intel(R) SGX SDK and Intel(R) SGX SDK Installer
- To build Intel(R) SGX SDK with default configuration, enter the following command:
```
  $ make sdk
```
You can find the three flavors of tools and libraries generated in the `build` directory.

- This repository supports to build the Intel(R) SGX SDK with below three combinations:
  * `USE_OPT_LIBS=0` --- build SDK using SGXSSL and open sourced String/Math
  * `USE_OPT_LIBS=1` --- build SDK using optimized IPP crypto and open sourced String/Math
  * `USE_OPT_LIBS=2` --- build SDK with no mitigation using SGXSSL and optimized String/Math
  * `USE_OPT_LIBS=3` --- build SDK with no mitigation using IPP crypto and optimized String/Math
  The default build uses `USE_OPT_LIBS=1`, if you directly type `$ make sdk` as above.
  You can switch to the other build combinations instead by entering the following command:
```
  $ make sdk USE_OPT_LIBS=0
```
or
```
  $ make sdk_no_mitigation USE_OPT_LIBS=2
```
or
```
  $ make sdk_no_mitigation USE_OPT_LIBS=3
```
  **Note**: Building the Intel(R) SGX PSW with open sourced SGXSSL/string/math libraries is not supported.
  **Note**: Building mitigation SDK with `USE_OPT_LIBS=2` or `USE_OPT_LIBS=3` is not allowed.

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
  The build above uses prebuilt Intel(R) Architecture Enclaves(LE/PvE/QE/PCE) - the files ``psw/ae/data/prebuilt/libsgx_*.signed.so``, which have been signed by Intel in advance.
- To build those enclaves by yourself (without a signature), first you need to install latest Intel(R) SGX SDK from the [Intel(R) SGX SDK](https://software.intel.com/en-us/sgx-sdk/download) and then build PSW with the default configuration. After that, you can build each Architecture Enclave by using the `make` command from the corresponding folder:
```
  $ cd psw/ae/le
  $ make
```
- To build the Intel(R) SGX PSW installer, enter the following command:
  * On Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04 and Debian 10:
   ```
  $ make deb_psw_pkg
  ```
  You can find the generated Intel(R) SGX PSW installers located under `linux/installer/deb/libsgx-urts`, `linux/installer/deb/libsgx-enclave-common`, `linux/installer/deb/libsgx-uae-service`, `linux/installer/deb/libsgx-epid`, `linux/installer/deb/libsgx-launch`, `linux/installer/deb/libsgx-quote-ex` and `linux/installer/deb/sgx-aesm-service` respectively.

  **Note**: Besides the Intel(R) SGX PSW installer, the above command generates another debug symbol package named ``package-name-dbgsym_${version}-${revision}_amd64.ddeb`` for debug purpose.
  **Note**: Starting with the 2.10 release, besides the Intel(R) SGX PSW installer, the above command generates [SGXDataCenterAttestationPrimitives](https://github.com/intel/SGXDataCenterAttestationPrimitives/) installers as well.
  **Note**: On Debian 10, the default PATH environment may not include /sbin. In this case, before trigger the build, please add /sbin to PATH environment by `export PATH=$PATH:/sbin`.
  **Note**: The above command builds the Intel(R) SGX PSW with default configuration firstly and then generates the target PSW Installer. To build the Intel(R) SGX PSW Installer without optimization and with full debug information kept in the tools and libraries, enter the following command:
  ```
  $ make deb_psw_pkg DEBUG=1
  ```
  * On Red Hat Enterprise Linux 9.2, CentOS Stream 9, CentOS 8.3, Anolis OS 8.6 and SUSE Linux Enterprise Server 15.4:
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
  * On Ubuntu 20.04:
  ```
  deb [trusted=yes arch=amd64] file:/PATH_TO_LOCAL_REPO focal main
  ```
  * On Ubuntu 22.04:
  ```
  deb [trusted=yes arch=amd64] file:/PATH_TO_LOCAL_REPO jammy main
  ```
  * On Ubuntu 24.04:
  ```
  deb [trusted=yes arch=amd64] file:/PATH_TO_LOCAL_REPO noble main
  ```
  * On Debian 10:
  ```
  deb [trusted=yes arch=amd64] file:/PATH_TO_LOCAL_REPO buster main
  ```
  After that, you need to update the apt:
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
  * On Red Hat Enterprise Linux 9.2, CentOS Stream 9, CentOS 8.3, Anolis OS 8.6:
  ```
  $ sudo yum-config-manager --add-repo file://PATH_TO_LOCAL_REPO
  ```
  * On SUSE Linux Enterprise Server 15.4, you need to replace LOCAL_REPO_ALIAS with proper alias name for the local repo:
  ```
  $ sudo zypper addrepo PATH_TO_LOCAL_REPO LOCAL_REPO_ALIAS
  ```
- To ignore the gpgcheck when you install the package, enter the following command:
  * On Red Hat Enterprise Linux 9.2, CentOS Stream 9, CentOS 8.3, Anolis OS 8.6:
  ```
  $ sudo yum --nogpgcheck install <package>
  ```
  * On SUSE Linux Enterprise Server 15.4:
  ```
  $ sudo zypper --no-gpg-checks install <package>
  ```

Install the Intel(R) SGX SDK
------------------------
### Prerequisites
- Ensure that you have one of the following operating systems:
  * Ubuntu\* 20.04 LTS Desktop 64bits
  * Ubuntu\* 20.04 LTS Server 64bits
  * Ubuntu\* 22.04 LTS Server 64bits
  * Ubuntu\* 24.04 LTS Server 64bits
  * Red Hat Enterprise Linux Server release 9.2 64bits
  * CentOS Stream 9 64bits
  * CentOS 8.3 64bits
  * SUSE Linux Enterprise Server 15.4 64bits
  * Anolis OS 8.6 64bits
  * Debian 10 64bits
- Use the following command to install the required tool to use Intel(R) SGX SDK:
  * On Debian 10:
  ```
    $ sudo apt-get install build-essential python3
    $ sudo update-alternatives --install /usr/bin/python python /usr/bin/python3 1
  ```
   * On Ubuntu 20.04, Ubuntu 22.04 and Ubuntu 24.04:
  ```
    $ sudo apt-get install build-essential python-is-python3
  ```
  * On Red Hat Enterprise Linux 9.2 and CentOS Stream 9:
  ```
     $ sudo yum groupinstall 'Development Tools'
     $ sudo yum install python3
  ```
  * On CentOS 8.3 and Anolis OS 8.6:
  ```
     $ sudo yum groupinstall 'Development Tools'
     $ sudo yum install python3
     $ sudo alternatives --set python /usr/bin/python3
  ```
  * On SUSE Linux Enterprise Server 15.4:
  ```
     $ sudo zypper install --type pattern devel_basis
     $ sudo zypper install python3
     $ sudo update-alternatives --install /usr/bin/python python /usr/bin/python3 1
  ```

### Install the Intel(R) SGX SDK
To install the Intel(R) SGX SDK, invoke the installer, as follows:
```
$ cd linux/installer/bin
$ ./sgx_linux_x64_sdk_${version}.bin
```
The above command requires you to specify the installation path. You can use the following command
to use the non-interactive installation mode:
```
$ cd linux/installer/bin
$ ./sgx_linux_x64_sdk_${version}.bin --prefix {SDK_INSTALL_PATH_PREFIX}
```
NOTE: You need to set up the needed environment variables before compiling your code. To do so, run:
```
  $ source ${sgx-sdk-install-path}/environment
```

### Test the Intel(R) SGX SDK Package with the Code Samples
- Compile and run each code sample in Simulation mode to make sure the package works well:
```
  $ cd ${sgx-sdk-install-path}/SampleCode/LocalAttestation
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
  $ cd ${sgx-sdk-install-path}/SampleCode/LocalAttestation
  $ make
  $ cd bin
  $ ./app
```
   Use similar commands for other code samples.
   **Note:** On Ubuntu 22.04 or any distro with systemd v248 or later, /dev/sgx_enclave is only accessible by users in the group "sgx". The enclave app should be run with a uid in the sgx group.
   ```
   # check systemd version:
   $ systemctl --version
   # add sgx group to user if it's 248 or above:
   $ sudo usermod -a -G sgx <user name>
   ```


Install the Intel(R) SGX PSW
----------------------------
### Prerequisites
- Ensure that you have one of the following operating systems:
  * Ubuntu\* 20.04 LTS Desktop 64bits
  * Ubuntu\* 20.04 LTS Server 64bits
  * Ubuntu\* 22.04 LTS Server 64bits
  * Ubuntu\* 24.04 LTS Server 64bits
  * Red Hat Enterprise Linux Server release 9.2 64bits
  * CentOS Stream 9 64bits
  * CentOS 8.3 64bits
  * SUSE Linux Enterprise Server 15.4 64bits
  * Anolis OS 8.6 64bits
  * Debian 10 64bits
- Ensure that you have a system with the following required hardware:
  * 6th Generation Intel(R) Core(TM) Processor or newer
- Configure the system with the **Intel SGX hardware enabled** option and install Intel(R) SGX driver in advance.
  See the earlier topic, *Build and Install the Intel(R) SGX Driver*, for information on how to install the Intel(R) SGX driver.
- Install the library using the following command:
  * On Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04 and Debian 10:
  ```
    $ sudo apt-get install libssl-dev libcurl4-openssl-dev libprotobuf-dev
  ```
  * On Red Hat Enterprise Linux 9.2:
  ```
    $ sudo yum install openssl-devel libcurl-devel protobuf-devel
  ```
  * On CentOS Stream 9:
  ```
    $ sudo dnf install libcurl-devel protobuf-devel
  ```
  * On CentOS 8.3:
  ```
    $ sudo dnf --enablerepo=powertools install libcurl-devel protobuf-devel
  ```
  * On Anolis OS 8.6:
  ```
    $ sudo dnf --enablerepo=PowerTools install libcurl-devel protobuf-devel
  ```
  * On SUSE Linux Enterprise Server 15.4:
  ```
    $ sudo zypper install libopenssl-devel libcurl-devel protobuf-devel
  ```

### Install the Intel(R) SGX PSW
The SGX PSW provides 3 services: launch, EPID-based attestation, and algorithm agnostic attestation. Starting with the 2.8 release, the SGX PSW is split into smaller packages and the user can choose which features and services to install. There are 2 methods to install the required packages: Using individual packages or using the local repo generated by the build system. Using the local repo is recommended since the system will resolve the dependencies automatically. Currently, we support .deb and .rpm based repos.

#### Using the local repo(recommended)

|   |Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04 and Debian 10|Red Hat Enterprise Linux 9.2, CentOS Stream 9, CentOS 8.3 and Anolis OS 8.6| SUSE Linux Enterprise Server 15|
| ------------ | ------------ | ------------ | ------------ |
|launch service |apt-get install libsgx-launch libsgx-urts|yum install libsgx-launch libsgx-urts|zypper install libsgx-launch libsgx-urts|
|EPID-based attestation service|apt-get install libsgx-epid libsgx-urts|yum install libsgx-epid libsgx-urts|zypper install libsgx-epid libsgx-urts|
|algorithm agnostic attestation service|apt-get install libsgx-quote-ex libsgx-urts|yum install libsgx-quote-ex libsgx-urts|zypper install libsgx-quote-ex libsgx-urts|
|DCAP ECDSA-based service |apt-get install libsgx-dcap-ql|yum install libsgx-dcap-ql|zypper install libsgx-dcap-ql|

Optionally, you can install *-dbgsym or *-debuginfo packages to get the debug symbols, and install *-dev or *-devel packages to get the header files for development.

#### Using the individual packages
Please refer [Intel_SGX_Installation_Guide_Linux](https://download.01.org/intel-sgx/latest/linux-latest/docs/) for detail.

#### Upgrade from a legacy installation
Sometimes we will split old package into smaller ones or move file between different packages. In such cases, you will encounter error messages like: "dpkg: error processing archive ....(--unpack): trying to overwrite ...". You can use 2 methods to address it.
* Uninstall the old installation first, then install new packages.
* Add ``-o Dpkg::Options::="--force-overwrite"`` option to overwrite existing files and use “``dist-upgrade``” instead of "upgrade" to install new packages when upgrading. In short, you should use this command:
```
apt-get dist-upgrade -o Dpkg::Options::="--force-overwrite"
```
#### Configure the installation
Some packages are configured with recommended dependency on other packages that are not required for certain usage. For instance, the background daemon is not required for container usage. It will be installed by default, but you can drop it by using the additional option during the installation.
* On Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04 and Debian 10:
```
  --no-install-recommends
```
* On Red Hat Enterprise Linux 9.2, CentOS Stream 9, CentOS 8.3 and Anolis OS 8.6:
```
  --setopt=install_weak_deps=False
```
* On SUSE Linux Enterprise Server 15.4:
```
  --no-recommends
```

### ECDSA attestation
To enable ECDSA attestation
- Ensure that you have the following required hardware:
  * 8th Generation Intel(R) Core(TM) Processor or newer with **Flexible Launch Control** support*
  * Intel(R) Atom(TM) Processor with **Flexible Launch Control** support*
- To use ECDSA attestation, you must install Intel(R) Software Guard Extensions Driver for Data Center Attestation Primitives (Intel(R) SGX DCAP).
Please follow the [Intel(R) SGX DCAP Installation Guide for Linux* OS](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf) to install the Intel(R) SGX DCAP driver.

**NOTE**: If you had already installed Intel(R) SGX driver without ECDSA attestation, please uninstall the driver firstly and then install the Intel(R) SGX DCAP driver. Otherwise the newly installed Intel(R) SGX DCAP driver will be unworkable.

- Install Quote Provider Library(QPL). You can use your own customized QPL or use default QPL provided by Intel(libsgx-dcap-default-qpl)

- Install PCK Caching Service. For how to install and configure PCK Caching
Service, please refer to [SGXDataCenterAttestationPrimitives](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/DCAP_1.21/QuoteGeneration/pccs)
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
