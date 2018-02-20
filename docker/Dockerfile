FROM ubuntu:16.04 as builder

RUN apt-get update && \
    apt-get install -y git build-essential ocaml automake autoconf libtool libcurl4-openssl-dev libprotobuf-dev libprotobuf-c0-dev protobuf-compiler curl make g++ unzip wget libssl-dev python


WORKDIR /linux-sgx
ADD . .
ARG optlib_name=optimized_libs-2.1.1.tar
ARG ae_file_name=prebuilt-ae-2.1.1.tar
ARG server_url_path=https://download.01.org/intel-sgx/linux-2.1.1/
ARG optlib_sha256=239cae39f87934d56c4eb919a4702c6ac82c19957b9a8d56c02b10eb4e27f573
ARG ae_sha256=f95589a69a8a8767815fe3bccf32bac5c9709022f9f32ae1a726b1da7955200b

RUN wget $server_url_path/$optlib_name && \
    wget $server_url_path/$ae_file_name && \
    echo "${optlib_sha256}  ${optlib_name}">checksum && \
    echo "${ae_sha256}  ${ae_file_name}">>checksum && \
    sha256sum checksum && \
    tar -xf $optlib_name && \
    tar -xf $ae_file_name && \
    rm $optlib_name $ae_file_name

RUN make psw_install_pkg && \
    make aesm_install_pkg && \
    make sdk_install_pkg

FROM ubuntu:16.04 as aesm 
RUN apt-get update && \
    apt-get install -y g++ \
                       libcurl4-openssl-dev \
                       libprotobuf9v5 \
                       libssl-dev \
                       make \
                       module-init-tools
 
WORKDIR /installer
COPY --from=builder /linux-sgx/linux/installer/bin/*.bin ./
RUN ./sgx_linux_x64_psw*.bin
RUN ./sgx_linux_x64_aesm*.bin

USER aesmd
CMD /opt/intel/sgxaesm/aesm/aesm_service --no-daemon

FROM ubuntu:16.04 as sample
RUN apt-get update && \
    apt-get install -y g++ \
                       libcurl4-openssl-dev \
                       libprotobuf9v5 \
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
