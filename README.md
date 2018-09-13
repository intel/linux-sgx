Intel(R) Software Guard Extensions for Linux\* OS
================================================

# linux-sgx

Introduction
------------
Intel(R) Software Guard Extensions (Intel(R) SGX) is an Intel technology for application developers seeking to protect select code and data from disclosure or modification.

The Linux\* Intel(R) SGX software stack is comprised of the Intel(R) SGX driver, the Intel(R) SGX SDK, and the Intel(R) SGX Platform Software (PSW). The Intel(R) SGX SDK and Intel(R) SGX PSW are hosted in the [linux-sgx](https://github.com/01org/linux-sgx) project.

The [linux-sgx-driver](https://github.com/01org/linux-sgx-driver) project hosts the out-of-tree driver for the Linux\* Intel(R) SGX software stack, which will be used until the driver upstreaming process is complete. 

The repository provides a reference implementation of a Launch Enclave for 'Flexible Launch Control' under [psw/ae/ref_le](psw/ae/ref_le). The reference LE implemenation can be used as a basis for enforcing different launch control policy by the platform developer or owner. To build and try it by yourself, please refer to the [ref_le.md](psw/ae/ref_le/ref_le.md) for details.

License
-------
See [License.txt](License.txt) for details.

Contributing
-------
See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

Documentation
-------------
- [Intel(R) SGX for Linux\* OS](https://01.org/intel-softwareguard-extensions) project home page on [01.org](https://01.org)
- [Intel(R) SGX Programming Reference](https://software.intel.com/sites/default/files/managed/48/88/329298-002.pdf)

Build and Install the Intel(R) SGX Driver
-----------------------------------------
Follow the instructions in the [linux-sgx-driver](https://github.com/01org/linux-sgx-driver) project to build and install the Intel(R) SGX driver.

Build the Intel(R) SGX SDK and Intel(R) SGX PSW Package
-------------------------------------------------------
### Prerequisites:
- Ensure that you have one of the following required operating systems:  
  * Ubuntu\* 16.04 LTS Desktop 64bits
  * Ubuntu\* 16.04 LTS Server 64bits
  * Ubuntu\* 18.04 LTS Desktop 64bits
  * Ubuntu\* 18.04 LTS Server 64bits
  * Red Hat Enterprise Linux Server release 7.4 64bits
  * CentOS 7.5 64bits
  * Fedora 27 Server 64bits
  * SUSE Linux Enterprise Server 12 64bits

- Use the following command(s) to install the required tools to build the Intel(R) SGX SDK:  
  * On Ubuntu 16.04 
  ```
    $ sudo apt-get install build-essential ocaml automake autoconf libtool wget python libssl-dev
  ```
  * On Ubuntu 18.04:
  ```
    $ sudo apt-get install build-essential ocaml ocamlbuild automake autoconf libtool wget python libssl-dev
  ```
  * On Red Hat Enterprise Linux 7.4 and CentOS 7.5:
  ```
    $ sudo yum groupinstall 'Development Tools'
    $ sudo yum install ocaml ocaml-ocamlbuild wget python openssl-devel
  ```
  * On Fedora 27:
  ```
    $ sudo yum groupinstall 'C Development Tools and Libraries'
    $ sudo yum install ocaml ocaml-ocamlbuild redhat-rpm-config openssl-devel wget python
  ```
  * On SUSE Linux Enterprise Server 12:
  ```
    $ sudo zypper install --type pattern devel_basis
    $ sudo zypper install ocaml ocaml-ocamlbuild automake autoconf libtool wget python libopenssl-devel
  ```
- Use the following command to install additional required tools to build the Intel(R) SGX PSW:  
  * On Ubuntu 16.04 and Ubuntu 18.04:
  ```
    $ sudo apt-get install libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper
  ```
  * On Red Hat Enterprise Linux 7.4, CentOS 7.5 and Fedora 27:
  ```
    $ sudo yum install openssl-devel libcurl-devel protobuf-devel
  ```
  * On SUSE Linux Enterprise Server 12:
  ```
    $ sudo zypper install libopenssl-devel libcurl-devel protobuf-devel
  ```
- Use the script ``download_prebuilt.sh`` inside source code package to download prebuilt binaries to prebuilt folder  
  You may need set an https proxy for the `wget` tool used by the script (such as ``export https_proxy=http://test-proxy:test-port``)  
```
  $ ./download_prebuilt.sh
```

### Build the Intel(R) SGX SDK and Intel(R) SGX PSW
The following steps describe how to build the Intel(R) SGX SDK and PSW. You can build the project according to your requirements.  
- To build both Intel(R) SGX SDK and PSW with default configuration, enter the following command:  
```
  $ make  
```  
  You can find the tools and libraries generated in the `build/linux` directory.     
  **Note**: You can also go to the `sdk` folder and use the `make` command to build the Intel(R) SGX SDK component only. However, building the PSW component is dependent on the result of building the Intel(R) SGX SDK.  

- This repository supports to build the Intel(R) SGX SDK based on either precompiled optimized IPP/string/math libraries or open sourced version of SGXSSL/string/math libraries. 
  The default build uses precompiled optimized libraries, which are downloaded by the script ``./download_prebuilt.sh``.
  You can also use the open sourced version implementation instead by entering the following command:
```
  $ make USE_OPT_LIBS=0
```
  **Note**: Building the Intel(R) SGX PSW with open sourced SGXSSL/string/math libraries is not supported. The above command builds Intel(R) SGX SDK only and the build of PSW part will be skipped.

- To build Intel(R) SGX SDK and PSW with debug information, enter the following command:  
```
  $ make DEBUG=1
```
- To clean the files generated by previous `make` command, enter the following command:  
```
  $ make clean
```

- The build above uses prebuilt Intel(R) Architecture Enclaves(LE/PvE/QE/PCE/PSE-OP/PSE-PR) and applet(PSDA) - the files ``psw/ae/data/prebuilt/libsgx_*.signed.so`` and ``psw/ae/data/prebuilt/PSDA.dalp``, which have been signed by Intel in advance.
  To build those enclaves by yourself (without a signature), first you need to build both Intel(R) SGX SDK and PSW with the default configuration. After that, you can build each Architecture Enclave by using the `make` command from the corresponding folder:
```
  $ cd psw/ae/le
  $ make
``` 

### Build the Intel(R) SGX SDK Installer
To build the Intel(R) SGX SDK installer, enter the following command:
```
$ make sdk_install_pkg
```
You can find the generated Intel(R) SGX SDK installer ``sgx_linux_x64_sdk_${version}.bin`` located under `linux/installer/bin/`, where `${version}` refers to the version number.

**Note**: The above command builds the Intel(R) SGX SDK with default configuration firstly and then generates the target SDK Installer. To build the Intel(R) SGX SDK Installer with debug information kept in the tools and libraries, enter the following command:
```
$ make sdk_install_pkg DEBUG=1
```

### Build the Intel(R) SGX PSW Installer
To build the Intel(R) SGX PSW installer, enter the following command:
- On Ubuntu 16.04 and Ubuntu 18.04:
  ```
  $ make deb_sgx_enclave_common_pkg
  ```
  You can find the generated Intel(R) SGX PSW installer ``libsgx-enclave-common_${version}-${revision}_amd64.deb`` located under `linux/installer/deb/libsgx-enclave-common`, where `${version}` refers to the version number and the `${revision}` refers to the revision number of the package.   
  **Note**: On Ubuntu 18.04, besides the Intel(R) SGX PSW installer, the above command generates another debug symbol package named ``libsgx-enclave-common-dbgsym_${version}-${revision}_amd64.ddeb`` for debug purpose. On Ubuntu 16.04, if you want to keep debug symbols in the Intel(R) SGX PSW installer, before building the Intel(R) SGX PSW, you need to export an environment variable to ensure the debug symbols not stripped:
   ```
   $ export DEB_BUILD_OPTIONS="nostrip"
   ```
  **Note**: The above command builds the Intel(R) SGX PSW with default configuration firstly and then generates the target PSW Installer. To build the Intel(R) SGX PSW Installer without optimization and with full debug information kept in the tools and libraries, enter the following command:
  ```
  $ make deb_sgx_enclave_common_pkg DEBUG=1
  ```
- On Red Hat Enterprise Linux 7.4 and CentOS 7.5:
- On Fedora 27:
- On SUSE Linux Enterprise Server 12:
  ```
  $ make psw_install_pkg
  ```
  You can find the generated Intel(R) SGX PSW installer ``sgx_linux_x64_psw_${version}.bin`` located under `linux/installer/bin/`, where `${version}` refers to the version number.

  **Note**: The above command builds the Intel(R) SGX PSW with default configuration firstly and then generates the target PSW Installer. To build the Intel(R) SGX PSW Installer with debug information kept in the tools and libraries, enter the following command:
  ```
  $ make psw_install_pkg DEBUG=1
  ```
To build the Intel(R) SGX PSW development installer, enter the following command:
- On Ubuntu 16.04 and Ubuntu 18.04:
  ```
  $ make deb_sgx_enclave_common_dev_pkg
  ```
  You can find the generated Intel(R) SGX PSW development installer ``libsgx-enclave-common-dev_${version}-${revision}_${arch}.deb`` located under `linux/installer/deb/libsgx-enclave-common-dev`.

Install the Intel(R) SGX SDK
------------------------
### Prerequisites
- Ensure that you have one of the following operating systems:  
  * Ubuntu\* 16.04 LTS Desktop 64bits
  * Ubuntu\* 16.04 LTS Server 64bits
  * Ubuntu\* 18.04 LTS Desktop 64bits
  * Ubuntu\* 18.04 LTS Server 64bits
  * Red Hat Enterprise Linux Server release 7.4 64bits
  * CentOS 7.5 64bits
  * Fedora 27 Server 64bits
  * SUSE Linux Enterprise Server 12 64bits
- Use the following command to install the required tool to use Intel(R) SGX SDK:
  * On Ubuntu 16.04 and Ubuntu 18.04:
  ```  
    $ sudo apt-get install build-essential python
  ```
  * On Red Hat Enterprise Linux 7.4 and CentOS 7.5:
  ```
     $ sudo yum groupinstall 'Development Tools'
     $ sudo yum install python 
  ```
  * On Fedora 27:
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
  * Red Hat Enterprise Linux Server release 7.4 64bits
  * CentOS 7.5 64bits
  * Fedora 27 Server 64bits
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
  * On Red Hat Enterprise Linux 7.4, CentOS 7.5 and Fedora 27:  
  ```
    $ sudo yum install openssl-devel libcurl-devel protobuf-devel
  ```
  * On SUSE Linux Enterprise Server 12:  
  ```
    $ sudo zypper install libopenssl-devel libcurl-devel protobuf-devel
  ```
- `iclsClient` and `JHI` are optional prerequisite components and are needed if you need to use Intel(R) SGX Platform Service. To install these components:  
  Ensure `mei_me` driver is enabled and `/dev/mei0` exists.  
  Download [iclsClient](https://software.intel.com/en-us/sgx-sdk/download) and install it using the following commands:  
  * On Ubuntu 16.04 and Ubuntu 18.04:
  ```
    $ sudo apt-get install alien
    $ sudo alien --scripts iclsClient-1.45.449.12-1.x86_64.rpm
    $ sudo dpkg -i iclsclient_1.45.449.12-2_amd64.deb
  ```
  * On Red Hat Enterprise Linux 7.4, CentOS 7.5 and Fedora 27:  
  ```
    $ sudo yum install iclsClient-1.45.449.12-1.x86_64.rpm
  ```
  * On SUSE Linux Enterprise Server 12:  
  ```
    $ sudo zypper install iclsClient-1.45.449.12-1.x86_64.rpm
  ```
  Download source code from [dynamic-application-loader-host-interface](https://github.com/01org/dynamic-application-loader-host-interface) project. In the source code folder, build and install the `JHI` service using the following commands:
  * On Ubuntu 16.04 and Ubuntu 18.04:
  ```
    $ sudo apt-get install uuid-dev libxml2-dev cmake pkg-config
    $ cmake .;make;sudo make install;sudo systemctl enable jhi
  ```
  * On Red Hat Enterprise Linux 7.4, CentOS 7.5 and Fedora 27:  
  ```
    $ sudo yum install libuuid-devel libxml2-devel cmake pkgconfig
    $ cmake .;make;sudo make install;sudo ldconfig;sudo systemctl enable jhi
  ```
  * On SUSE Linux Enterprise Server 12:  
  ```
    $ sudo zypper install libuuid-devel libxml2-devel cmake pkg-config
    $ cmake .;make;sudo make install;sudo ldconfig;sudo systemctl enable jhi
  ```

### Install the Intel(R) SGX PSW
To install the Intel(R) SGX PSW, invoke the installer with root privilege: 
- On Ubuntu 16.04 and Ubuntu 18.04:
  ```
  $ cd linux/installer/deb/libsgx-enclave-common
  $ sudo dpkg -i ./libsgx-enclave-common_${version}-${revision}_amd64.deb
  ```
  **NOTE**: To debug with sgx-gdb on Ubuntu 16.04, you need to ensure the Intel(R) SGX PSW is built under the condition that the environment variable ``DEB_BUILD_OPTIONS="nostrip"`` is set. On Ubuntu 18.04, you need to install the debug package by entering the following command:
  ```
  $ cd linux/installer/deb/libsgx-enclave-common
  $ sudo dpkg -i ./libsgx-enclave-common-dbgsym_${version}-${revision}_amd64.ddeb
  ```
- On Red Hat Enterprise Linux 7.4 and CentOS 7.5:
- On Fedora 27:
- On SUSE Linux Enterprise Server 12:
  ```
  $ cd linux/installer/bin
  $ sudo ./sgx_linux_x64_psw_${version}.bin
  ```
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
