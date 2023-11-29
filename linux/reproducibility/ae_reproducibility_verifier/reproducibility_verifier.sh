#!/usr/bin/env bash
#
# Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
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

usage()
{
	cat << EOM
Usage:
    ./reproducibility_verifier.sh intel_signed_ae user_build_unsigned_ae user_private_key intel_ae_config_xml [output_dir]

The script is to verify Intel(R) prebuilt AEs are:
    * Built using the open source codebase and toolchain
    * Signed using the open source enclave config.xml

Arguments:
    intel_signed_ae         : Required. Intel(R) prebuilt AE (*.signed.so) to be verified.
    user_build_unsigned_ae  : Required. Your self-build AE (*.so) in an SGX docker container.
    user_private_key        : Required. Your private key (PEM format) for signing user_build_unsigned_ae.
    intel_ae_config_xml     : Required. The opensource enclave config.xml of Intel(R) prebuilt AE.
    output_dir              : Optional. The folder the results generated in. Use ./output as default.

Note: 
    If no arguments, './reproducibility_verifier.sh' will show the usage.

Result:
    * If the verification succeeds:
      Display info: Reproducibility Verification PASSED!
      Exit status: 0
    * If the verification fails:
      Display info: Reproducibility Verification FAILED!
      Exit status: 1
    * Other Error:
      Display the specific error info
      Exit status: 2
    You can find the detailed result in the output_dir folder.
EOM
}

is_file_existed()
{
	file=$1
	err_msg=$2	
	if [ ! -f $file ]; then
		echo -e "Error: $file is not found. $err_msg\n"
		exit 2
	fi
}

check_cmd_status()
{
	status=$1
	err_msg=$2
	if [ $status -ne 0 ]; then
		echo -e "Error: $err_msg with return value $status!\n"
		exit 2
	fi
}

check_input_parameter()
{
	is_file_existed $1 "Please check the path for $2 is correct!"
	echo -e "* $2\t: $1"
	
}

prepare()
{
	if [ $# == 0 ]; then
		usage
		exit 2 
	fi

	# check input parameter list
	check_input_parameter $intel_signed_ae 'intel signed AE'
	check_input_parameter $user_unsigned_ae 'user unsigned AE'
	check_input_parameter $user_key 'user private key'
	check_input_parameter $intel_config 'intel config.xml'
	if [ -z "$output_dir" ]; then
		output_dir='output'
	fi
	user_signed_ae=$output_dir'/user_ae.signed.so'
	metadata1_orig=$output_dir'/intel_metadata_orig.txt'
	metadata2_orig=$output_dir'/user_metadata_orig.txt'
	metadata1=$output_dir'/intel_metadata.txt'
	metadata2=$output_dir'/user_metadata.txt'
	metadata_diff=$output_dir'/metadata_diff.txt'

	if [ 0"${SGX_SDK}" = 0"" ]; then
		echo -e "Error: \$SGX_SDK is not found, please ensure Intel(R) SGX SDK is installed and the required environment variables are set!\n"
		exit 2
	fi
	
	if [ -d $output_dir ]; then
		rm -rf $output_dir/*
	fi
	mkdir -p $output_dir
}

extract_enclave_metadata()
{
	# get the whole enclave metadata including keys related
	is_file_existed $1 "the signed enclave for sgx dump is not existed"
	${SGX_SDK}/bin/x64/sgx_sign dump -enclave $1 -dumpfile $2 > /dev/null 2>&1
	check_cmd_status $? "sgn_sign dump the signed enclave failed"

	# extract part of enclave metadata by excluding below fields:
	# 	enclave_css.header.date
	# 	enclave_css.enclave_css.key.modulus
	# 	enclave_css.key.exponent
	# 	enclave_css.key.signature
	# 	enclave_css.buffer.q1
	# 	enclave_css.buffer.q2
	is_file_existed $2 "the original enclave_metadata file is not existed for sed to extract"
	sed -n '/metadata->magic_num/,/metadata->enclave_css.header.module_vendor/p;/metadata->enclave_css.header.header2/,/metadata->enclave_css.header.hw_version/p;/metadata->enclave_css.body.misc_select/,/metadata->enclave_css.body.isv_svn/p;' $2 > $3
	check_cmd_status $? "sed the original enclave metadata failed!"
}

extract_intel_enclave_metadata()
{
	extract_enclave_metadata $intel_signed_ae $metadata1_orig $metadata1
}

extract_user_enclave_metadata()
{
	# sgx_sign user's unsigned AE with Intel config.xml and user's private key
	${SGX_SDK}/bin/x64/sgx_sign sign -enclave $user_unsigned_ae -key $user_key -config $intel_config -out $user_signed_ae > /dev/null 2>&1
	check_cmd_status $? "sgx_sign sign user_build_ae failed"

	# extract user signed AE's metadata
	extract_enclave_metadata $user_signed_ae $metadata2_orig $metadata2
}

check_ae_reproducibility()
{
	is_file_existed $metadata1 "the intel ae metadata file is not existed for diff to compare"
	is_file_existed $metadata2 "the user ae metadata file is not existed for diff to compare"

	diff $metadata1 $metadata2 > $metadata_diff 2>&1
	diff_status=$? 
	if [ $diff_status -eq 0 ]; then
		echo -e "\nReproducibility Verification PASSED!\n"
		exit 0
	elif [ $diff_status -eq 1 ]; then
		echo -e "\nReproducibility Verification FAILED!\n"
		echo -e "Please find the diff contents in $metadata_diff"
		exit 1
	else
		echo -e "\nError: There was something wrong with the diff command!\n"
		exit 2
	fi
}



intel_signed_ae=$1
user_unsigned_ae=$2
user_key=$3
intel_config=$4
output_dir=$5

# Step 1: check input parameters and prepare enviroment 
prepare $@

# Step 2: extract Intel signed AE's metadata
extract_intel_enclave_metadata

# Step 3: sgx_sign user's self build AE and extract user signed AE's metadata
extract_user_enclave_metadata

# Step 4: compare metadata between intel signed ae and user signed ae 
check_ae_reproducibility
