#!/usr/bin/env bash
#
# Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#


set -e 

SCRIPT_DIR=$(dirname "$0")
source ${SCRIPT_DIR}/installConfig

PSW_DST_PATH=${SGX_PACKAGES_PATH}/${PSW_PKG_NAME}
AESM_PATH=$PSW_DST_PATH/aesm

# Install the AESM service
mkdir -p /var/opt/aesmd
cp -rf $AESM_PATH/data /var/opt/aesmd/
rm -rf $AESM_PATH/data
cp -rf $AESM_PATH/conf/aesmd.conf /etc/aesmd.conf
rm -rf $AESM_PATH/conf
chmod 0644 /etc/aesmd.conf
chmod 0750 /var/opt/aesmd

# By default the AESM's communication socket will be created in
# /var/run/aesmd.  Putting the socket in the aesmd sub-directory
# as opposed to directly in /var/run allows the user to create a
# mount a volume at /var/run/aesmd and thus expose the socket to
# a different filesystem or namespace, e.g. a Docker container.
mkdir -p /var/run/aesmd
chmod 0755 /var/run/aesmd

if [ -d /run/systemd/system ]; then
    systemctl stop aesmd &> /dev/null || echo
    AESMD_NAME=aesmd.service
    AESMD_TEMP=$AESM_PATH/$AESMD_NAME
    if [ -d /lib/systemd/system ]; then
        AESMD_DEST=/lib/systemd/system/$AESMD_NAME
    else
        AESMD_DEST=/usr/lib/systemd/system/$AESMD_NAME
    fi
    echo -n "Installing $AESMD_NAME service ..."
    sed -e "s:@aesm_folder@:$AESM_PATH:" \
        $AESMD_TEMP > $AESMD_DEST
    chmod 0644 $AESMD_DEST
    rm -f $AESMD_TEMP
    rm -f $AESM_PATH/aesmd.conf
    retval=$?
elif [ -d /etc/init/ ]; then
    /sbin/initctl stop aesmd &> /dev/null || echo
    AESMD_NAME=aesmd.conf
    AESMD_TEMP=$AESM_PATH/$AESMD_NAME
    AESMD_DEST=/etc/init/$AESMD_NAME
    echo -n "Installing $AESMD_NAME service ..."
    sed -e "s:@aesm_folder@:$AESM_PATH:" \
        $AESMD_TEMP > $AESMD_DEST
    chmod 0644 $AESMD_DEST
    rm -f $AESMD_TEMP
    rm -f $AESM_PATH/aesmd.service
    retval=$?
fi

if [ "X$retval" != "X" ]; then
    if [ $retval -ne 0 ]; then
        echo " failed."
        echo "Error: Failed to install $AESMD_NAME."
        exit 6
    fi
    echo " done."
else
    # Check the parameter
    for param; do
        if [ "${param}" == "--no-start-aesm" ]; then
            NO_START_AESM=true
            break
        fi
    done

    if [ "${NO_START_AESM}" == true ]; then
        echo "Warning: No systemctl/initctl to start AESM. You may start AESM manually, e.g., /opt/intel/sgxpsw/aesm/aesm_service --no-daemon"
    else
        echo "Error: Unsupported platform - neither systemctl nor initctl is found."
        exit 5
    fi
fi

#Install the assistance scripts
cp -rf $PSW_DST_PATH/udev /etc
rm -rf $PSW_DST_PATH/udev

if [ -d /run/systemd/system ]; then
    systemctl stop remount-dev-exec &> /dev/null || echo
    REMOUNT_DEV_EXEC_NAME=remount-dev-exec.service
    if [ -d /lib/systemd/system ]; then
        REMOUNT_DEV_EXEC_DEST=/lib/systemd/system/$REMOUNT_DEV_EXEC_NAME
    else
        REMOUNT_DEV_EXEC_DEST=/usr/lib/systemd/system/$REMOUNT_DEV_EXEC_NAME
    fi
    mv $PSW_DST_PATH/$REMOUNT_DEV_EXEC_NAME $REMOUNT_DEV_EXEC_DEST
    chmod 0644 $REMOUNT_DEV_EXEC_DEST
fi

cat > $PSW_DST_PATH/uninstall.sh <<EOF
#!/usr/bin/env bash
#
# Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#


if test \$(id -u) -ne 0; then
    echo "Root privilege is required."
    exit 1
fi

$PSW_DST_PATH/cleanup.sh

# Stop and disable remount-dev-exec service
if [ -d /run/systemd/system ]; then
    systemctl stop remount-dev-exec
    systemctl disable remount-dev-exec
fi

# Removing AESM configuration files
rm -f $AESMD_DEST
rm -f /etc/aesmd.conf

# Removing AESM internal folders
#rm -fr /var/opt/aesmd
rm -fr /var/run/aesmd

# Removing runtime libraries
rm -f /usr/{lib,lib64}/libsgx_uae_service.so
rm -f /usr/{lib,lib64}/libsgx_urts.so
rm -f /usr/{lib,lib64}/libsgx_enclave_common.so*
rm -f /usr/{lib,lib64}/libsgx_epid.so*
rm -f /usr/{lib,lib64}/libsgx_launch.so*
rm -f /usr/{lib,lib64}/libsgx_quote_ex.so*
rm -f /usr/lib/i386-linux-gnu/libsgx_uae_service.so
rm -f /usr/lib/i386-linux-gnu/libsgx_urts.so
rm -f /usr/lib/i386-linux-gnu/libsgx_enclave_common.so*
rm -f /usr/lib/i386-linux-gnu/libsgx_epid.so*
rm -f /usr/lib/i386-linux-gnu/libsgx_launch.so*
rm -f /usr/lib/i386-linux-gnu/libsgx_quote_ex.so*

# Removing the assistance scripts
rm -f /etc/udev/rules.d/91-sgx-enclave.rules
rm -f /etc/udev/rules.d/92-sgx-provision.rules
rm -f $REMOUNT_DEV_EXEC_DEST

# Removing AESM folder
rm -fr $PSW_DST_PATH

echo "Intel(R) SGX PSW uninstalled."
EOF

chmod +x $PSW_DST_PATH/uninstall.sh
chmod +x $PSW_DST_PATH/cleanup.sh

chmod +x $AESM_PATH/linksgx.sh

chmod +x $PSW_DST_PATH/startup.sh
$PSW_DST_PATH/startup.sh

# Enable and start remount-dev-exec service
if [ -d /run/systemd/system ]; then
    systemctl enable remount-dev-exec
    systemctl start remount-dev-exec
fi

$AESM_PATH/cse_provision_tool 2> /dev/null || true
rm -f $AESM_PATH/cse_provision_tool

echo -e "\nuninstall.sh script generated in $PSW_DST_PATH\n"

echo -e "Installation is successful!"

rm -fr $PSW_DST_PATH/scripts

exit 0
