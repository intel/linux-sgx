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
 
/* ====================================================================
 * Copyright (c) 1998-2017 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
 
/* Content from openssl-1.1.0e/crypto/include/internal/md32_common.h */
 
#ifndef SGX_PCL_MD32_COMMON_H
#define SGX_PCL_MD32_COMMON_H

#   define ROTATE(a,n)  ({ register unsigned int ret;   \
                                asm (                   \
                                "roll %1,%0"            \
                                : "=r"(ret)             \
                                : "I"(n), "0"((unsigned int)(a))        \
                                : "cc");                \
                           ret;                         \
                        })

#     define HOST_c2l(c,l)        ({ unsigned int r=*((const unsigned int *)(c)); \
                                   asm ("bswapl %0":"=r"(r):"0"(r));    \
                                   (c)+=4; (l)=r;                       })
#     define HOST_l2c(l,c)        ({ unsigned int r=(l);                  \
                                   asm ("bswapl %0":"=r"(r):"0"(r));    \
                                   *((unsigned int *)(c))=r; (c)+=4; r; })

int pcl_SHA256_Update(SHA256_CTX *c, void *data_, size_t len)
{
    unsigned char *data = (unsigned char *)data_;
    unsigned char *p;
    SHA_LONG l;
    size_t n;

    if (len == 0)
        return 1;

    l = (c->Nl + (((SHA_LONG) len) << 3)) & 0xffffffffUL;
    /*
     * 95-05-24 eay Fixed a bug with the overflow handling, thanks to Wei Dai
     * <weidai@eskimo.com> for pointing it out.
     */
    if (l < c->Nl)              /* overflow */
        c->Nh++;
    c->Nh += (SHA_LONG) (len >> 29); /* might cause compiler warning on
                                       * 16-bit */
    c->Nl = l;
/* PCL UNUSED START *
    n = c->num;
    if (n != 0) {
        p = (unsigned char *)c->data;

        if (len >= SHA_CBLOCK || len + n >= SHA_CBLOCK) {
            pcl_memcpy(p + n, data, SHA_CBLOCK - n);
            pcl_sha256_block_data_order(c, p, 1);
            n = SHA_CBLOCK - n;
            data += n;
            len -= n;
            c->num = 0;
            /*
             * We use memset rather than OPENSSL_cleanse() here deliberately.
             * Using OPENSSL_cleanse() here could be a performance issue. It
             * will get properly cleansed on finalisation so this isn't a
             * security problem.
             * /
            pcl_memset(p, 0, SHA_CBLOCK); /* keep it zeroed * /
        } else {
            pcl_memcpy(p + n, data, len);
            c->num += (unsigned int)len;
            return 1;
        }
    }
/* PCL UNUSED END */
    n = len / SHA_CBLOCK;
    if (n > 0) {
        pcl_sha256_block_data_order(c, data, n);
        n *= SHA_CBLOCK;
        data += n;
        len -= n;
    }

    if (len != 0) {
        p = (unsigned char *)c->data;
        c->num = (unsigned int)len;
        pcl_memcpy(p, data, len);
    }
    return 1;
}

int pcl_SHA256_Final(unsigned char *md, SHA256_CTX *c)
{
    unsigned char *p = (unsigned char *)c->data;
    size_t n = c->num;

    p[n] = 0x80;                /* there is always room for one */
    n++;

    if (n > (SHA_CBLOCK - 8)) {
        pcl_memset(p + n, 0, SHA_CBLOCK - n);
        n = 0;
        pcl_sha256_block_data_order(c, p, 1);
    }
    pcl_memset(p + n, 0, SHA_CBLOCK - 8 - n);

    p += SHA_CBLOCK - 8;
/* PCL UNUSED START *
#if   defined(DATA_ORDER_IS_BIG_ENDIAN)
/* PCL UNUSED END   */
    (void)HOST_l2c(c->Nh, p);
    (void)HOST_l2c(c->Nl, p);
/* PCL UNUSED START *
#elif defined(DATA_ORDER_IS_LITTLE_ENDIAN)
    (void)HOST_l2c(c->Nl, p);
    (void)HOST_l2c(c->Nh, p);
#endif
/* PCL UNUSED END   */
    p -= SHA_CBLOCK;
    pcl_sha256_block_data_order(c, p, 1);
    c->num = 0;
    pcl_memset(p, 0, SHA_CBLOCK);
/* PCL UNUSED START *
#ifndef HASH_MAKE_STRING
# error "HASH_MAKE_STRING must be defined!"
#else
/* PCL UNUSED END   */
    HASH_MAKE_STRING(c, md);
/* PCL UNUSED START *
#endif
/* PCL UNUSED END   */

    return 1;
}

#define MD32_REG_T int

#endif // #ifndef SGX_PCL_MD32_COMMON_H

