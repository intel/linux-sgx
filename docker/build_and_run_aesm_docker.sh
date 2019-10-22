#!/bin/sh
set -e
docker build --target aesm --build-arg https_proxy=$https_proxy \
              --build-arg http_proxy=$http_proxy -t sgx_aesm -f ./Dockerfile ../

# Create a temporary directory on the host that will be mounted
# into both the AESM and sample containers at /var/run/aesmd so
# that the AESM socket will be visible to the sample container
# in the expected location.  It is critical that /tmp/aesmd be
# world writable as UIDs may be shifted in the container.
mkdir -p -m 777 /tmp/aesmd
chmod -R -f 777 /tmp/aesmd
docker run --env http_proxy --env https_proxy --device=/dev/sgx -v /tmp/aesmd:/var/run/aesmd -it sgx_aesm
