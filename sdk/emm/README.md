Introduction
---------------------------------
This directory contains an implementation of the Enclave Memory Manager proposed in [this PR](https://github.com/openenclave/openenclave/pull/3991)

The instructions here are for developing and testing the EMM functionality only. Consult the main README for general usages.

**Note:** The kernel patch series for upstream are under review on LKML in [this thread](https://lore.kernel.org/linux-sgx/cover.1644274683.git.reinette.chatre@intel.com/). Please refer to the cover letter of the series for changes between versions.

This EMM implementation is based on the testing branch for the kernel hosted [here](https://github.com/rchatre/linux/tree/sgx/sgx2_submitted_v2_plus_rwx), which includes a temporary patch to allow RWX pages.  As the kernel interfaces evolve, the EMM implementation and/or interface may change.

Prerequisites
-------------------------------

#### Build and install kernel with EDMM support
On Ubuntu 18.04/20.04, follow the general instructions from [here](https://wiki.ubuntu.com/KernelTeam/GitKernelBuild) with these changes.

- For step 1, clone this kernel repo and checkout the branch with sgx EDMM support
```
$ git clone https://github.com/rchatre/linux.git
$ cd linux
$ git checkout sgx/sgx2_submitted_v2_plus_rwx
```

- For step 6, modify .config to set "CONFIG_X86_SGX=y".

#### Verify kernel build and EDMM support
At the root of the kernel source repo,
```
$ cd tools/testing/selftests/sgx/ && make
#./test_sgx
```
#### Add udev rules to map sgx device nodes and set right permissions
Download [10-sgx.rules](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/driver/linux/10-sgx.rules) and activate it as follows.
```
$ sudo cp  10-sgx.rules /etc/udev/rules.d
$ sudo groupadd sgx_prv
$ sudo udevadm trigger
```
Build and Install SDK and PSW
------------------------------

#### Clone linux-sgx repo and checkout edmm branch
```
$ git clone https://github.com/intel/linux-sgx.git $repo_root
$ cd $repo_root
$ git checkout edmm_v2
```
Following steps assume $repo_root is the top directory of the linux-sgx repo you cloned.

#### To build and install SDK with EDMM support
```
$ cd $repo_root
$ make preparation
$ make sdk_install_pkg_no_mitigation
$ cd linux/installer/bin
$ ./sgx_linux_x64_sdk_2.15.100.3.bin
# follow its prompt to set SDK installation destination directory, $SGX_SDK
$ source $SGX_SDK/environment
```

#### To build and setup libsgx_enclave_common and libsgx_urts
To test EMM functionalities without involving remote attestation, we only need libsgx_enclave_common and libsgx_urts built and point LD_LIBRARY_PATH to them.

```
$ cd $repo_root/psw/urts/linux
$ make
$ cd <repo_root>/build/linux
$ ln -s libsgx_enclave_common.so libsgx_enclave_common.so.1
$ export LD_LIBRARY_PATH=<repo_root>/build/linux/
```

#### To build and run API tests
```
$ cd $repo_root/sdk/emm/api_tests/
$ make
$ ./test_mm_api
# or run tests in loop in background
$ nohup bash ./test_loop.sh 1000 &
#check results in nohup log:
$ tail -f nohup.out
```

Limitations of current implementation
---------------------------------------
1. EMM holds a global recursive mutex for the whole duration of each API invocation.
	- No support for concurrent operations (modify type/permissions, commit and commit_data) on different regions.
2. EMM internally uses the default heap and stack during its internal operations
	- The initial heap and stack should be sufficient to bootstrap EMM initializations
	- Book-keeping for heap should be created when RTS is initialized.
		- RTS calls mm_init_ema to create region for the static heap (EADDed), and mm_alloc to reserve COMMIT_ON_DEMAND for dynamic heap.
	- Stack expansion should be done in 1st phase exception handler and use a reserved static stack
		- Such that stack is not overrun in sgx_mm API calls during stack expansion.
3. EMM requires all RTS allocations(with SGX_EMA_SYSTEM flag) are reserved up front during RTS/enclave initializations.
	- EMM won't allocate any user requested region below the highest address in RTS regions.
	- EMM won't serve any user request unless at least one RTS region is reserved.
4. EMM relies on vDSO interface to guarantee that fault handler is called on the same OS thread where fault happened.
	- This is due to the use of the global recursive mutex. If fault handler comes in from different thread while the mutex is held, it will deadlock.
	- Note a #PF could happen when more stack is needed inside EMM functions while the mutex is locked.
		- vDSO user handler should ensure it re-enters enclave with the original TCS and on the same OS thread.
		- To avoid potential deadlocks, no other mutex/lock should be used in this path from user handler to first phase exception handler inside enclave.
5. Not optimized for performance
6. No extensive validation, failure or incorrect error codes possible for corner cases.

Notes on Intel SDK specific implementation
-----------------------------------------
1. 	Intel SDK RTS abstraction layer mutex implementation is a spinlock because there is no built-in OCalls for wait/wake on OS event.
2. 	Intel SDK signing tool reserves all unused address space as guard pages, leaving no space for user allocation. In this implementation, we simply changed tRTS to leave majority of that space as free. In future, we may need change the signing tool to encode this info in the metadata.
3. 	API tests are built with Intel SDK. Though most of tests are RTS independent, the TCS related tests use hardcoded Intel thread context layout info.
4. All make files assume linux-sgx repo layout and environment.


