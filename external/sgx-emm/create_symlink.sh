#!/usr/bin/env bash
#
# Copyright (C) 2011-2022 Intel Corporation. All rights reserved.
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

emm_src=external/sgx-emm/emm_src
common_inc=common/inc
common_internal=common/inc/internal

ln -sf ../../$emm_src/include/sgx_mm.h $common_inc/sgx_mm.h
ln -sf ../../$emm_src/include/sgx_mm_primitives.h $common_inc/sgx_mm_primitives.h
ln -sf ../../$emm_src/include/sgx_mm_rt_abstraction.h $common_inc/sgx_mm_rt_abstraction.h

ln -sf ../../../$emm_src/include/bit_array.h $common_internal/bit_array.h
ln -sf ../../../$emm_src/include/bit_array_imp.h $common_internal/bit_array_imp.h
ln -sf ../../../$emm_src/include/ema.h $common_internal/ema.h
ln -sf ../../../$emm_src/include/ema_imp.h $common_internal/ema_imp.h
ln -sf ../../../$emm_src/include/emm_private.h $common_internal/emm_private.h
