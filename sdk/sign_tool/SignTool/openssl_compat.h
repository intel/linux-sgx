#ifndef _OPENSSL_COMPAT_H_
#define _OPENSSL_COMPAT_H_

#include <openssl/engine.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
void RSA_get0_key(const RSA *r,
                  const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);

#endif
#endif
