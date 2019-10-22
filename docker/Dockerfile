FROM ubuntu:18.04 as builder

RUN apt-get update
RUN apt-get install -y build-essential ocaml ocamlbuild automake autoconf libtool wget python libssl-dev 
RUN apt-get install -y git libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper cmake


WORKDIR /linux-sgx
ADD . .

RUN ./download_prebuilt.sh

RUN make sdk_install_pkg

WORKDIR /opt/intel
RUN sh -c 'echo yes | /linux-sgx/linux/installer/bin/sgx_linux_x64_sdk_*.bin'

RUN cd /linux-sgx && \
    make psw_install_pkg

FROM ubuntu:18.04 as aesm 
RUN apt-get update && \
    apt-get install -y libssl1.1 libcurl4 libprotobuf10 module-init-tools make
 
WORKDIR /installer
COPY --from=builder /linux-sgx/linux/installer/bin/*.bin ./
RUN ./sgx_linux_x64_psw*.bin

USER aesmd
WORKDIR /opt/intel/sgxpsw/aesm/
ENV LD_LIBRARY_PATH=.
CMD /opt/intel/sgxpsw/aesm/aesm_service --no-daemon
#CMD /bin/bash

FROM ubuntu:18.04 as sample
RUN apt-get update && \
    apt-get install -y g++ \
                       libcurl4-openssl-dev \
                       libprotobuf-dev \
                       libssl-dev \
                       make \
                       module-init-tools
WORKDIR /opt/intel
COPY --from=builder /linux-sgx/linux/installer/bin/*.bin ./
RUN ./sgx_linux_x64_psw*.bin
RUN sh -c 'echo yes | ./sgx_linux_x64_sdk_*.bin'

RUN cd sgxsdk/SampleCode/SampleEnclave && \
    SGX_DEBUG=0 SGX_MODE=HW SGX_PRERELEASE=1 make
CMD cd /opt/intel/sgxsdk/SampleCode/SampleEnclave && \
    ./app
