/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdlib.h>
#include <string.h>
#include "ippcp.h"

extern "C" void secure_free_rsa_pri2_key(int p_byte_size, IppsRSAPrivateKeyState *pri_key2)
{
    if (p_byte_size <= 0 || pri_key2 == NULL) {
        if (pri_key2)
            free(pri_key2);
        return;
    }

    int rsa2_size = 0;
    if (ippsRSA_GetSizePrivateKeyType2(p_byte_size * 8, p_byte_size * 8, &rsa2_size) != ippStsNoErr) {
        free(pri_key2);
        return;
    }
    /* Clear the buffer before free. */
    memset_s(pri_key2, rsa2_size, 0, rsa2_size);
    free(pri_key2);
    return;
}

extern "C" void secure_free_rsa_pub_key(int n_byte_size, int e_byte_size, IppsRSAPublicKeyState *pub_key)
{
    if (n_byte_size <= 0 || e_byte_size <= 0 || pub_key == NULL) {
        if (pub_key)
            free(pub_key);
        return;
    }
    int rsa_size = 0;
    if (ippsRSA_GetSizePublicKey(n_byte_size * 8, e_byte_size * 8, &rsa_size) != ippStsNoErr) {
        free(pub_key);
        return;
    }
    /* Clear the buffer before free. */
    memset_s(pub_key, rsa_size, 0, rsa_size);
    free(pub_key);
    return;
}
