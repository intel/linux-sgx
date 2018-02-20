# Deploy SGX enclaves in containers

Files in this directory demostrate how to deploy SGX enclave applications in docker containers.

These shell scripts demostrate steps to build and start containers for different scenarios
- [build_and_run_aesm_docker.sh](../docker/build_and_run_aesm_docker.sh) - build and run AESM in docker, using bin installer
-  [build_and_run_aesm_docker_deb.sh](../docker/build_and_run_aesm_docker_deb.sh) - build and run AESM in docker, using deb installer
-  [build_and_run_sample_docker.sh](../docker/build_and_run_sample_docker.sh) - build and run SampleEnclave example in docker, using bin installer
- [build_and_run_ra.sh](../docker/build_and_run_ra.sh) - build and run RemoteAttestation example in docker, using bin installer
- [build_compose_run.sh](../docker/build_compose_run.sh) - use docker composer to bring up separate containers for AESM and SampleEnclave example.

There are also Kubernates deployment files to demostrate different ways to deploy SGX containers on a minikube node. See [Kubernates deployments](#kubernates-deployments)

## General considerations

### Handling AESM dependency

On CPUs with no flexible launch control support (Kabe Lake, Skylake CPUs), or systems with [SGX out-of-tree driver](https://github.com/intel/linux-sgx-driver), the AESM service is needed to run and host the launch enclave.

Also for applications requiring remote attestation, AESM with a quoting enclave or a quote generation library such as the one provided by [Intel DCAP project](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/QuoteGeneration) is needed to generate quote for the enclave to be attested. In case of quote generation library, it needs be compiled in with the app hosting the attestee enclave. Please refer to [Intel SGX SDK documentation](https://software.intel.com/sgx) for details on remote attestation

It is recommended to either run AESM in separate container or directly on the host and expose the named socket to application containers by mounting the same Socket file on the host filesystem, /tmp/aesmd in this demo.

It is not recommended, but in any case you want to run AESM and application together in the same container, please refer to docker documentation on [multi-service container](https://docs.docker.com/config/containers/multi-service_container/)

### Support for containers in different VMs on the same host

SGX KVM support is not yet available. This means we can only have SGX applications isolated at container (process boundary) level.
This demo does not show how to deploy SGX app containers into different VMs.  

Another issue to support VMs: to connect to AESM running in separate VM, we need expose its Unix socket as TCP sockt listening for incoming requests.

Potential solution: Use a proxy server container (e.g., socat) on the same VM as AESM to do the listening and forwarding of the requests to the AESM socket. On the application VM, also a proxy client container (e.g., socat) to forward the request to the proxy server. This is demostrated in util/set_up_aesm_socat.sh and util/run_sample_with_socat.sh scripts.

### Scale deployment to multi-host clusters

This demo is designed for single physical node only.

It should be straightforward to scale an SGX application that is stateless: just create more instances of containers on more nodes.

To scale a stateful SGX application, particularly if the enclave it hosts need to access states shared  with its peers, one needs to carefully design a strategy to handle shared states among enclave instances. In addition to address general stateful application scaling issues, the enclaves need to establish trust and protected channels before sharing state between each other. This can become very application specific and is out of scope of this demo.

To handle AESM dependency in mulit-host cluster scenarios, one needs ensure app containers only communicate AESM containers on the same physical machine as quotes and launch token are only valid on the same physical machine. 

Similarly for applications with enclaves doing local attestation, one must bundle those containers (possible in the same k8s pod) to run on the same physical machine.


### Handling SGX device node

All SGX applications need access to the SGX device nodes exposed by kernel space driver. Those nodes need be mapped and mounted inside containers.

1. DCAP driver: /dev/sgx
2. OOT driver: /dev/isgx
3. Inkernel: /dev/sgx/enclave (for all SGX app containers), /dev/sgx/provision (for apps with enclaves accessing the SGX provisioning keys)

Note docker can pass devices nodes to container from "docker run" command line, but kubernetes requires containers running with "priviledged" mode, which is the approach used in this demo for minikube deployments.

## Build and run docker container directly

### Docker files

Dockerfile is a multi-stage docker file that specifies 3 image build targets:
1. builder: builds psw and sdk bin installers from source, with necessary prebuilt AEs and libs downloaded from 01.org.
2. aesm: takes psw installer from builder, install and run the aesm deamon.
3. sample: takes sdk installer from build, build and run the SampleEnclave app

build_and_run_aesm_docker.sh shows how to build and run the aesm image. This will start an aesm service listening to named socket, mounted to /var/run/aesmd in the container from host /tmp/aesmd

build_and_run_sample_docker.sh shows how to build and run the SampleEnclave app inside container with locally built sgx_sample image.

### Docker composer files

docker-compose.yml can be used with docker composer to start both aesm and sample app in separate containers.
build_compose_run.sh demostrate its usage.

## Kubernates deployments

There are 3 different deployment files and they can be used to test on a minikube node started with "minikube start --vm-driver=none". Note in future when KVM supports SGX, we can remove the option "--vm-driver=none).

1. aesm-deployment.yaml: start aesm container/pod using local docker sgx_aesm image
2. sample-deploymen.yaml:start sample container/pod using local docker sgx_sample image. Note this deployment will wait for /tmp/aemsd/aesm.socket created by aesm
3. all-in-one.yaml: start both aesm and sample containers in one pod. 

Please refer to [minikube docs](https://kubernetes.io/docs/tasks/tools/install-minikube/) for installation, startup, managing deployments.

After installing minikube, kubectl following instructions, here are typical steps to deploy pods of aesm and sample app to the minikube.
```
$ sudo minikube start --vm-driver=none
$ sudo minikube dashboard # to start the dashboard, optional, useful to see status of pods, deployments
$ sudo kubectl apply -f aesm-deployment.yaml
$ sudo kubectl apply -f sample-deployment.yaml #order does not matter
```
To deploy the all-in-one pod, replace the last two commands with:
```$ sudo kubectl apply -f all-in-one.yaml```

