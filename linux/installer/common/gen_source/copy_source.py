#!/usr/bin/env python
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

import os
import shutil
import argparse

def copy_directory(src, dst):
	if os.path.isdir(src) == True:
		if os.path.exists(dst) == False:
			os.makedirs(dst)

		for item in os.listdir(src):
			copy_directory((os.path.join(src, item)).replace("\\", "/"), (os.path.join(dst, item)).replace("\\", "/"))
	else:
		shutil.copy(src, dst)
	return

def copy_files():
	with open(bom_file, 'r') as f:
		next(f)
		for line in f:
			if line == "\n":
				continue
			src = line.split('\t')[0].replace("\\", "/").replace("<deliverydir>/", src_path + "/")
			dst = line.split('\t')[1].replace("\\", "/").replace("<installdir>/", dst_path + "/")

			if os.path.realpath(dst).startswith(os.path.realpath(src) + "/") == True:
				print("Error: destination {} is a sub-directory of source {}!".format(dst, src)) 
				exit(1)

			if os.path.exists(src) == True:
				if os.path.isdir(src) == False :
					if os.path.exists(os.path.dirname(dst)) == False:
						os.makedirs(os.path.dirname(dst))
					shutil.copy(src, dst)
				else:
					copy_directory(src, dst)
			else:
				print("Error: src directory/file {} does not exist!".format(src))
				exit(1)
	return

def parse_args():
	global bom_file
	global src_path
	global dst_path
	global cleanup

	parser = argparse.ArgumentParser()
	parser.add_argument("--bom-file", metavar="[BOM file]", type=argparse.FileType('r'), dest="bom_file", required=True,
						help="The BOM file used to generate the source tree.")
	parser.add_argument("--src-path", metavar="[source path]", dest="src_path", required=True,
						help="The path for the original source code.")
	parser.add_argument("--dst-path", metavar="[destination path]", dest="dst_path", required=True,
						help="The detestation path of the generated source tree.")
	parser.add_argument("--cleanup", action="store_true", default=False, dest="cleanup",
						help="Whether to cleanup the source tree.")
	args = parser.parse_args()

	if os.path.isfile(os.path.abspath(args.bom_file.name)) == False:
		parser.error("Invalid argument for option '--bom-file %s'." %(args.bom_file.name))
		exit(1)
	if os.path.isdir(os.path.abspath(args.src_path)) == False:
		parser.error("Invalid argument for option '--src-path %s'." %(args.src_path))
		exit(1)
	if os.path.exists(args.dst_path) == True and os.path.isdir(os.path.abspath(args.dst_path)) == False:
		parser.error("Invalid argument for option '--dst-path %s'." %(args.dst_path))
		exit(1)

	bom_file = args.bom_file.name
	src_path = args.src_path
	dst_path = args.dst_path
	cleanup = args.cleanup

	if cleanup == True and os.path.exists(dst_path) == True:
		shutil.rmtree(os.path.abspath(dst_path))

	if os.path.exists(dst_path) == False:
		os.makedirs(dst_path)
	return

if __name__ == "__main__":
	parse_args()
	copy_files()

	exit(0)
