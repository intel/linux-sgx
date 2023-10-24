/**
 *
 * MIT License
 *
 * Copyright (c) Open Enclave SDK contributors.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE
 *
 */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <string.h>
#include <sgx_error.h>
#include "cert_header.h"
#include <openssl/sha.h>
#include "cbor.h"
#include "sgx_quote_4.h"
#include "sgx_quote_5.h"

typedef struct _cert
{
    uint64_t magic;
    X509* x509;
} cert_t;


static void _cert_init(cert_t* impl, X509* x509)
{
    impl->magic = SGX_CERT_MAGIC;
    impl->x509 = x509;
}

static bool _cert_is_valid(const cert_t* impl)
{
    return impl && (impl->magic == SGX_CERT_MAGIC) && impl->x509;
}

static void _cert_clear(cert_t* impl)
{
    if (impl)
    {
        impl->magic = 0;
        impl->x509 = NULL;
    }
}

typedef struct _cert_chain
{
    uint64_t magic;
    STACK_OF(X509) * sk;
} cert_chain_t;

static bool _cert_chain_is_valid(const cert_chain_t* impl)
{
    return impl && (impl->magic == SGX_CERT_CHAIN_MAGIC) && impl->sk;
}

/* Clone the certificate to clear any verification state */
static X509* _clone_x509(X509* x509)
{
    X509* ret = NULL;
    BIO* out = NULL;
    BIO* in = NULL;
    BUF_MEM* mem;

    if (!x509)
        goto done;

    if (!(out = BIO_new(BIO_s_mem())))
        goto done;

    if (!PEM_write_bio_X509(out, x509))
        goto done;

    if (!BIO_get_mem_ptr(out, &mem))
        goto done;

    if (mem->length > INT_MAX)
        goto done;

    if (!(in = BIO_new_mem_buf(mem->data, (int)mem->length)))
        goto done;

    ret = PEM_read_bio_X509(in, NULL, 0, NULL);

done:

    if (out)
        BIO_free(out);

    if (in)
        BIO_free(in);

    return ret;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
/* Needed because some versions of OpenSSL do not support X509_up_ref() */
static int X509_up_ref(X509* x509)
{
    if (!x509)
        return 0;

    CRYPTO_add(&x509->references, 1, CRYPTO_LOCK_X509);
    return 1;
}

static const STACK_OF(X509_EXTENSION) * X509_get0_extensions(const X509* x)
{
    if (!x->cert_info)
    {
        return NULL;
    }
    return x->cert_info->extensions;
}

#endif

static STACK_OF(X509) * _clone_chain(STACK_OF(X509) * chain)
{
    STACK_OF(X509)* sk = NULL;
    int n = sk_X509_num(chain);

    if (!(sk = sk_X509_new(NULL)))
        return NULL;

    for (int i = 0; i < n; i++)
    {
        X509* x509;

        if (!(x509 = sk_X509_value(chain, (int)i)))
            return NULL;

        if (!(x509 = _clone_x509(x509)))
            return NULL;

        if (!sk_X509_push(sk, x509))
            return NULL;
    }

    return sk;
}

static sgx_status_t _verify_cert(
    X509* cert,
    STACK_OF(X509) * chain_,
    const sgx_crl_t* const* crls,
    size_t num_crls)
{
    sgx_status_t result = SGX_ERROR_UNEXPECTED;
    X509_STORE_CTX* ctx = NULL;
    X509_STORE* store = NULL;
    X509* x509 = NULL;
    STACK_OF(X509)* chain = NULL;

    /* Clone the certificate to clear any cached verification state */
    if (!(x509 = _clone_x509(cert)))
        goto end;

    /* Clone the chain to clear any cached verification state */
    if (chain_ && !(chain = _clone_chain(chain_)))
        goto end;

    /* Create a store for the verification */
    if (!(store = X509_STORE_new()))
        goto end;

    /* Create a context for verification */
    if (!(ctx = X509_STORE_CTX_new()))
        goto end;

    /* Initialize the context that will be used to verify the certificate */
    if (!X509_STORE_CTX_init(ctx, store, NULL, NULL))
        goto end;

    /* Create a store with CRLs if needed */
    if (crls && num_crls)
    {
        X509_VERIFY_PARAM* verify_param = NULL;

        for (size_t i = 0; i < num_crls; i++)
        {
            crl_t* crl_impl = (crl_t*)crls[i];

            /* X509_STORE_add_crl manages its own addition refcount */
            if (!X509_STORE_add_crl(store, crl_impl->crl))
                goto end;
        }

        /* Get the verify parameter (must not be null) */
        if (!(verify_param = X509_STORE_CTX_get0_param(ctx)))
            goto end;

        X509_VERIFY_PARAM_set_flags(verify_param, X509_V_FLAG_CRL_CHECK);
        X509_VERIFY_PARAM_set_flags(verify_param, X509_V_FLAG_CRL_CHECK_ALL);
    }

    /* Inject the certificate into the verification context */
    X509_STORE_CTX_set_cert(ctx, x509);

    /* Set the CA chain into the verification context */
    if (chain)
        X509_STORE_CTX_trusted_stack(ctx, chain);
    else
        X509_STORE_add_cert(store, x509);

    /* Finally verify the certificate */
    if (!X509_verify_cert(ctx))
    {
        int errorno = X509_STORE_CTX_get_error(ctx);
        if (errorno != X509_V_OK)
            goto end;
    }

    result = SGX_SUCCESS;

end:
    if (x509)
        X509_free(x509);

    if (chain)
        sk_X509_pop_free(chain, X509_free);

    if (store)
        X509_STORE_free(store);

    if (ctx)
        X509_STORE_CTX_free(ctx);

    return result;
}


sgx_status_t sgx_read_cert_in_der(
    sgx_cert_t* cert,
    const void* der_data,
    size_t der_size)
{
    sgx_status_t result = SGX_ERROR_UNEXPECTED;
    cert_t* impl = (cert_t*)cert;
    X509* x509 = NULL;
    unsigned char* p = NULL;

    /* Zero-initialize the implementation */
    if (impl)
        impl->magic = 0;

    /* Check parameters */
    if (!der_data || !der_size || der_size > INT_MAX || !cert)
        return SGX_ERROR_INVALID_PARAMETER;

    /* Initialize OpenSSL (if not already initialized) */
    //sgxssl_crypto_initialize();

    p = (unsigned char*)der_data;

    /* Convert the PEM BIO into a certificate object */
    if (!(x509 = d2i_X509(NULL, (const unsigned char**)&p, (int)der_size)))
        goto end;

    _cert_init(impl, x509);
    x509 = NULL;

    result = SGX_SUCCESS;

end:

    X509_free(x509);

    return result;
}

sgx_status_t sgx_cert_free(sgx_cert_t* cert)
{
    sgx_status_t result = SGX_ERROR_UNEXPECTED;
    cert_t* impl = (cert_t*)cert;

    /* Check parameters */
    if (!_cert_is_valid(impl))
        goto end;

    /* Free the certificate */
    X509_free(impl->x509);
    _cert_clear(impl);

    result = SGX_SUCCESS;

end:
    return result;
}

sgx_status_t sgx_cert_verify(
    sgx_cert_t* cert,
    sgx_cert_chain_t* chain,
    const sgx_crl_t* const* crls,
    size_t num_crls)
{
    sgx_status_t result = SGX_ERROR_UNEXPECTED;
    cert_t* cert_impl = (cert_t*)cert;
    cert_chain_t* chain_impl = (cert_chain_t*)chain;

    /* Check for invalid cert parameter */
    if (!_cert_is_valid(cert_impl))
        return SGX_ERROR_INVALID_PARAMETER;

    /* Check for invalid chain parameter */
    if (chain && !_cert_chain_is_valid(chain_impl))
        return SGX_ERROR_INVALID_PARAMETER;

    /* Verify the certificate */
    _verify_cert(
        cert_impl->x509,
        (chain_impl != NULL ? chain_impl->sk : NULL),
        crls,
        num_crls);

    result = SGX_SUCCESS;

    return result;
}

static sgx_status_t compare_cert_pubkey_against_cbor_claim_hash(
    const uint8_t* pem_pub_key,
    size_t pem_pub_key_len,
    cbor_item_t* cbor_hash_entry)
{
    uint8_t pk_der[PUB_KEY_MAX_SIZE] = {0};
    size_t pk_der_size = 0;
    unsigned char *p_sha = NULL;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    cbor_item_t* cbor_hash_alg_id = NULL;
    cbor_item_t* cbor_hash_value  = NULL;

    if (PEM2DER_PublicKey_converter(pem_pub_key, pem_pub_key_len, pk_der, &pk_der_size))
      goto out;

    if (!cbor_isa_array(cbor_hash_entry) || !cbor_array_is_definite(cbor_hash_entry)
            || cbor_array_size(cbor_hash_entry) != 2) {
        return SGX_ERROR_TLS_X509_INVALID_EXTENSION;
    }

    cbor_hash_alg_id = cbor_array_get(cbor_hash_entry, /*index=*/0);
    if (!cbor_hash_alg_id || !cbor_isa_uint(cbor_hash_alg_id)) {
        ret = SGX_ERROR_TLS_X509_INVALID_EXTENSION;
        goto out;
    }

    cbor_hash_value = cbor_array_get(cbor_hash_entry, /*index=*/1);
    if (!cbor_hash_value || !cbor_isa_bytestring(cbor_hash_value)
            || !cbor_bytestring_is_definite(cbor_hash_value)) {
        ret = SGX_ERROR_TLS_X509_INVALID_EXTENSION;
        goto out;
    }

    uint8_t sha[SHA512_DIGEST_LENGTH]; /* enough to hold SHA-256, -384, or -512 */
    size_t sha_size;
    size_t temp_size;

    uint64_t hash_alg_id;
    switch (cbor_int_get_width(cbor_hash_alg_id)) {
        case CBOR_INT_8:  hash_alg_id = cbor_get_uint8(cbor_hash_alg_id); break;
        case CBOR_INT_16: hash_alg_id = cbor_get_uint16(cbor_hash_alg_id); break;
        case CBOR_INT_32: hash_alg_id = cbor_get_uint32(cbor_hash_alg_id); break;
        case CBOR_INT_64: hash_alg_id = cbor_get_uint64(cbor_hash_alg_id); break;
        default:          ret = SGX_ERROR_TLS_X509_INVALID_EXTENSION; goto out;
    }

    switch (hash_alg_id) {
        case IANA_NAMED_INFO_HASH_ALG_REGISTRY_SHA256:
            sha_size = SHA256_DIGEST_LENGTH;
            break;
        case IANA_NAMED_INFO_HASH_ALG_REGISTRY_SHA384:
            sha_size = SHA384_DIGEST_LENGTH;
            break;
        case IANA_NAMED_INFO_HASH_ALG_REGISTRY_SHA512:
            sha_size = SHA512_DIGEST_LENGTH;
            break;
        default:
            ret = SGX_ERROR_TLS_X509_INVALID_EXTENSION;
            goto out;
    }

    temp_size = cbor_bytestring_length(cbor_hash_value);
    if (temp_size != sha_size) {
        ret = SGX_ERROR_TLS_X509_INVALID_EXTENSION;
        goto out;
    }

    switch (hash_alg_id) {
        case IANA_NAMED_INFO_HASH_ALG_REGISTRY_RESERVED:
        case IANA_NAMED_INFO_HASH_ALG_REGISTRY_SHA256:
            p_sha = SHA256(pk_der, pk_der_size, sha);
            break;
        case IANA_NAMED_INFO_HASH_ALG_REGISTRY_SHA384:
            p_sha = SHA384(pk_der, pk_der_size, sha);
            break;
        case IANA_NAMED_INFO_HASH_ALG_REGISTRY_SHA512:
            p_sha = SHA512(pk_der, pk_der_size, sha);
            break;
    }

    if (p_sha == NULL)
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto out;
    }

    if (memcmp(cbor_bytestring_handle(cbor_hash_value), sha, sha_size)) {
        ret = SGX_ERROR_INVALID_SIGNATURE;
        goto out;
    }

    ret = SGX_SUCCESS;
out:
    if (cbor_hash_alg_id) cbor_decref(&cbor_hash_alg_id);
    if (cbor_hash_value)  cbor_decref(&cbor_hash_value);
    return ret;
}


sgx_status_t extract_cbor_evidence_and_compare_hash(
            const uint8_t* cbor_evidence_buf,
            size_t evidence_buf_size,
            uint8_t* pem_pub_key,
            size_t pem_pub_key_len,
            uint8_t* out_quote,
            uint32_t* out_quote_size)
{
    /* for description of evidence format, see ttls.c:generate_cbor_evidence() */
    cbor_item_t* cbor_tagged_evidence = NULL;
    cbor_item_t* cbor_evidence = NULL;
    cbor_item_t* cbor_quote = NULL;
    cbor_item_t* cbor_claims = NULL; /* serialized CBOR map of claims (as bytestring) */
    cbor_item_t* cbor_claims_map = NULL;
    cbor_item_t* cbor_hash_entry = NULL;
    uint8_t* quote = NULL;
    sgx_status_t ret = SGX_SUCCESS;

    struct cbor_pair* claims_pairs = NULL;
    uint8_t* claims_buf = NULL;
    size_t claims_buf_size = 0;
    size_t quote_size = 0;

    if (evidence_buf_size == 0) return SGX_ERROR_UNEXPECTED;

    struct cbor_load_result cbor_result;
    cbor_tagged_evidence = cbor_load(cbor_evidence_buf, evidence_buf_size, &cbor_result);
    if (cbor_result.error.code != CBOR_ERR_NONE) {
        ret = (cbor_result.error.code == CBOR_ERR_MEMERROR) ? 
            SGX_ERROR_OUT_OF_MEMORY : SGX_ERROR_UNEXPECTED;
        goto out;
    }
    if (!cbor_isa_tag(cbor_tagged_evidence)
            || cbor_tag_value(cbor_tagged_evidence) != TCG_DICE_TAGGED_EVIDENCE_TEE_QUOTE_CBOR_TAG)     
    {
        ret = SGX_ERROR_TLS_X509_INVALID_EXTENSION;
        goto out;
    }

    cbor_evidence = cbor_tag_item(cbor_tagged_evidence);
    if (!cbor_evidence || !cbor_isa_array(cbor_evidence)
            || !cbor_array_is_definite(cbor_evidence)) {
        ret = SGX_ERROR_TLS_X509_INVALID_EXTENSION;
        goto out;
    }

    if (cbor_array_size(cbor_evidence) != 2) {
        ret = SGX_ERROR_TLS_X509_INVALID_EXTENSION;
        goto out;
    }

    cbor_quote = cbor_array_get(cbor_evidence, /*index=*/0);
    if (!cbor_quote || !cbor_isa_bytestring(cbor_quote) || !cbor_bytestring_is_definite(cbor_quote)
            || cbor_bytestring_length(cbor_quote) == 0) {
        ret = SGX_ERROR_TLS_X509_INVALID_EXTENSION;
        goto out;
    }

    quote_size = cbor_bytestring_length(cbor_quote);
    if (quote_size < QUOTE_MIN_SIZE) {
        ret = SGX_ERROR_TLS_X509_INVALID_EXTENSION;
        goto out;
    }
    quote = (uint8_t*)malloc(quote_size);
    if (!quote) {
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto out;
    }
    memcpy(quote, cbor_bytestring_handle(cbor_quote), quote_size);

    cbor_claims = cbor_array_get(cbor_evidence, /*index=*/1);
    if (!cbor_claims || !cbor_isa_bytestring(cbor_claims)
            || !cbor_bytestring_is_definite(cbor_claims)
            || cbor_bytestring_length(cbor_claims) == 0) {
        ret = SGX_ERROR_TLS_X509_INVALID_EXTENSION;
        goto out;
    }

    /* claims object is borrowed, no need to free separately */
    claims_buf    = cbor_bytestring_handle(cbor_claims);
    claims_buf_size = cbor_bytestring_length(cbor_claims);
    assert(claims_buf && claims_buf_size);

    /* verify that TEE quote corresponds to the attached serialized claims */
    ret = sgx_tls_compare_quote_hash(quote, claims_buf, claims_buf_size);
    if (ret != SGX_SUCCESS)
    {
        goto out;
    }
    /* parse and verify CBOR claims */
    cbor_claims_map = cbor_load(claims_buf, claims_buf_size, &cbor_result);
    if (cbor_result.error.code != CBOR_ERR_NONE) {
        ret = (cbor_result.error.code == CBOR_ERR_MEMERROR) ?
            SGX_ERROR_OUT_OF_MEMORY : SGX_ERROR_TLS_X509_INVALID_EXTENSION;
        goto out;
    }

    if (!cbor_isa_map(cbor_claims_map) || !cbor_map_is_definite(cbor_claims_map)
            || cbor_map_size(cbor_claims_map) < 1) {
        ret = SGX_ERROR_TLS_X509_INVALID_EXTENSION;
        goto out;
    }

    claims_pairs = cbor_map_handle(cbor_claims_map);
    for (size_t i = 0; i < cbor_map_size(cbor_claims_map); i++) {
        if (!claims_pairs[i].key || !cbor_isa_string(claims_pairs[i].key)
                || !cbor_string_is_definite(claims_pairs[i].key)
                || cbor_string_length(claims_pairs[i].key) == 0) {
            ret = SGX_ERROR_TLS_X509_INVALID_EXTENSION;
            goto out;
        }

        if (strncmp((char*)cbor_string_handle(claims_pairs[i].key), "pubkey-hash",
                    cbor_string_length(claims_pairs[i].key)) == 0) {
            /* claim { "pubkey-hash" : serialized CBOR array hash-entry (as CBOR bstr) } */
            if (!claims_pairs[i].value || !cbor_isa_bytestring(claims_pairs[i].value)
                    || !cbor_bytestring_is_definite(claims_pairs[i].value)
                    || cbor_bytestring_length(claims_pairs[i].value) == 0) {
                ret = SGX_ERROR_TLS_X509_INVALID_EXTENSION;
                goto out;
            }

            uint8_t* hash_entry_buf = cbor_bytestring_handle(claims_pairs[i].value);
            size_t hash_entry_buf_size = cbor_bytestring_length(claims_pairs[i].value);

            cbor_hash_entry = cbor_load(hash_entry_buf, hash_entry_buf_size, &cbor_result);
            if (cbor_result.error.code != CBOR_ERR_NONE) {
                ret = (cbor_result.error.code == CBOR_ERR_MEMERROR) ? SGX_ERROR_OUT_OF_EPC
                      : SGX_ERROR_TLS_X509_INVALID_EXTENSION;
                goto out;
            }

            ret = compare_cert_pubkey_against_cbor_claim_hash(pem_pub_key, pem_pub_key_len, cbor_hash_entry);
            if (ret != SGX_SUCCESS)
            {
                goto out;
            }
        }
    }

    memcpy(out_quote, quote, quote_size);
    *out_quote_size = (uint32_t)quote_size;
    ret = SGX_SUCCESS;

out:
    SGX_TLS_SAFE_FREE(quote);
    if (cbor_hash_entry)
        cbor_decref(&cbor_hash_entry);
    if (cbor_claims_map)
        cbor_decref(&cbor_claims_map);
    if (cbor_claims)
        cbor_decref(&cbor_claims);
    if (cbor_quote)
        cbor_decref(&cbor_quote);
    if (cbor_evidence)
        cbor_decref(&cbor_evidence);
    if (cbor_tagged_evidence)
        cbor_decref(&cbor_tagged_evidence);
    return ret;
}

sgx_status_t sgx_cert_get_public_key(
    const sgx_cert_t* cert,
    sgx_public_key_t* public_key)
{
    sgx_status_t result = SGX_ERROR_UNEXPECTED;
    const cert_t* impl = (const cert_t*)cert;
    EVP_PKEY* pkey = NULL;

    if (public_key)
        memset(public_key, 0, sizeof(sgx_public_key_t));

    if (!_cert_is_valid(impl) || !public_key) {
        result = SGX_ERROR_INVALID_PARAMETER;
        goto done;
    }

    if (!(pkey = X509_get_pubkey(impl->x509))) {
        result = SGX_ERROR_UNEXPECTED;
        goto done;
    }

    public_key->pkey = pkey;
    pkey = NULL;

    result = SGX_SUCCESS;

done:

    if (pkey)
    {
        EVP_PKEY_free(pkey);
    }

    return result;
}

sgx_status_t sgx_public_key_write_pem(
    const sgx_public_key_t* key,
    uint8_t* data,
    size_t* size)
{
    sgx_status_t result = SGX_ERROR_UNEXPECTED;
    BIO* bio = NULL;
    const sgx_public_key_t* impl = (const sgx_public_key_t*)key;
    const char null_terminator = '\0';

    /* If buffer is null, then size must be zero */
    if (!key || (!data && *size != 0)) {
        result = SGX_ERROR_INVALID_PARAMETER;
        goto done;
    }

    /* Create memory BIO object to write key to */
    if (!(bio = BIO_new(BIO_s_mem()))) {
        result = SGX_ERROR_UNEXPECTED;
        goto done;
    }

    /* Write key to BIO */
    if (!PEM_write_bio_PUBKEY(bio, impl->pkey)) {
        result = SGX_ERROR_UNEXPECTED;
        goto done;
    }

    /* Write a NULL terminator onto BIO */
    if (BIO_write(bio, &null_terminator, sizeof(null_terminator)) <= 0) {
        result = SGX_ERROR_UNEXPECTED;
        goto done;
    }

    /* Copy the BIO onto caller's memory */
    {
        BUF_MEM* mem;

        if (!BIO_get_mem_ptr(bio, &mem)) {
            result = SGX_ERROR_UNEXPECTED;
            goto done;
        }

        /* If buffer is too small */
        if (*size < mem->length)
        {
            *size = mem->length;

            result = SGX_ERROR_OUT_OF_MEMORY;
            goto done;
        }

        /* Copy result to output buffer */
        memcpy(data, mem->data, mem->length);
        *size = mem->length;
    }

    result = SGX_SUCCESS;

done:

    if (bio)
        BIO_free(bio);

    return result;
}


sgx_status_t sgx_cert_find_extension(
    const sgx_cert_t* cert,
    const char* oid,
    uint8_t* data,
    uint32_t* size)
{
    sgx_status_t result = SGX_ERROR_UNEXPECTED;
    const cert_t* impl = (const cert_t*)cert;
    const STACK_OF(X509_EXTENSION) * extensions;
    int num_extensions;

    /* Reject invalid parameters */
    if (!_cert_is_valid(impl) || !oid || !size) {
        result = SGX_ERROR_INVALID_PARAMETER;
        goto done;
    }

    /* Set a pointer to the stack of extensions (possibly NULL) */
    if (!(extensions = X509_get0_extensions(impl->x509)))
        goto done;

    /* Get the number of extensions (possibly zero) */
    num_extensions = sk_X509_EXTENSION_num(extensions);

    /* Find the certificate with this OID */
    for (int i = 0; i < num_extensions; i++)
    {
        X509_EXTENSION* ext;
        ASN1_OBJECT* obj;
        sgx_oid_string_t ext_oid;

        /* Get the i-th extension from the stack */
        if (!(ext = sk_X509_EXTENSION_value(extensions, i)))
            goto done;

        /* Get the OID */
        if (!(obj = X509_EXTENSION_get_object(ext)))
            goto done;

        /* Get the string name of the OID */
        if (!OBJ_obj2txt(ext_oid.buf, sizeof(ext_oid.buf), obj, 1))
            goto done;

        /* If found then get the data */
        if (strcmp(ext_oid.buf, oid) == 0)
        {
            ASN1_OCTET_STRING* str;

            /* Get the data from the extension */
            if (!(str = X509_EXTENSION_get_data(ext)))
                goto done;

            if (data)
            {
                memcpy(data, str->data, (size_t)str->length);
                *size = (size_t)str->length;
                result = SGX_SUCCESS;
                goto done;
            }
        }
    }

done:
    return result;
}

sgx_status_t sgx_get_pubkey_from_cert(
    const sgx_cert_t* cert,
    uint8_t* pem_data,
    size_t* pem_size)
{
    sgx_status_t result = SGX_ERROR_UNEXPECTED;
    sgx_public_key_t public_key;

    if (SGX_SUCCESS != sgx_cert_get_public_key(cert, &public_key)) {
        goto done;
    }
    
    if (SGX_SUCCESS != sgx_public_key_write_pem(&public_key, pem_data, pem_size)) {
        goto done;
    }

    result = SGX_SUCCESS;

done:

    if (public_key.pkey) {
        EVP_PKEY_free(public_key.pkey);
        public_key.pkey = NULL;
    }

    return result;
}

/* a common function to compare hash from target_buf with quote */
/* possible in_buf could be public_key for legacy or claims buf for interoperable ra-tls*/
sgx_status_t sgx_tls_compare_quote_hash(uint8_t *p_quote,
            uint8_t* in_buf, size_t in_buf_len)
{
    size_t report_data_size = 0;
    uint32_t quote_type = 0;
    uint8_t *p_report_data = NULL;
    uint8_t *hash_in_buf = NULL; // buf to store hash by target_buf
    unsigned char *p_sha = NULL;
    sgx_status_t ret = SGX_SUCCESS;

    if (p_quote == NULL) return SGX_ERROR_UNEXPECTED;

    quote_type = *(uint32_t *)(p_quote + 4 * sizeof(uint8_t));

    // get hash of cert pub key
    report_data_size = (quote_type == 0x81) ? SGX_REPORT2_DATA_SIZE : SGX_REPORT_DATA_SIZE;
    hash_in_buf = (uint8_t*)malloc(report_data_size);
    if (!hash_in_buf) {
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto done;
    }
    if (quote_type == 0x81) {
        uint16_t _version = 0;
        memcpy((void*)&_version, p_quote, sizeof(_version));

        if (_version == 5) 
        {
            p_report_data = (uint8_t*)&(((sgx_report2_body_v1_5_t*)&(((sgx_quote5_t*)p_quote)->body))->report_data);
        } else
        {
            p_report_data = (uint8_t*)(&((sgx_quote4_t *)p_quote)->report_body.report_data);
        }

        p_sha = SHA384(in_buf, in_buf_len,
                    reinterpret_cast<unsigned char *>(hash_in_buf));
        if (p_sha == NULL || 
                    memcmp(p_sha, hash_in_buf, SHA384_DIGEST_LENGTH) != 0) {
            ret = SGX_ERROR_UNEXPECTED;
            goto done;
        }
        if (memcmp(p_report_data, hash_in_buf, SHA384_DIGEST_LENGTH) != 0) {
            ret = SGX_ERROR_INVALID_SIGNATURE;
            goto done;
        }
    } else if (quote_type == 0x00)
    {
        p_report_data = (uint8_t*)(&((sgx_quote3_t *)p_quote)->report_body.report_data);
        p_sha = SHA256(in_buf, in_buf_len, reinterpret_cast<unsigned char *>(hash_in_buf));
        if (p_sha == NULL ||
                    memcmp(p_sha, hash_in_buf, SHA256_DIGEST_LENGTH) != 0) {
            ret = SGX_ERROR_UNEXPECTED;
            goto done;
        }
        // compare hash, only compare the first 32 bytes
        if (memcmp(p_report_data, hash_in_buf, SHA256_DIGEST_LENGTH) != 0) {
            ret = SGX_ERROR_INVALID_SIGNATURE;
            goto done;
        }
    }
    else {
        ret = SGX_ERROR_UNEXPECTED;
        goto done;
    }

done:
    SGX_TLS_SAFE_FREE(hash_in_buf);
    return ret;
}

// support functions
static char b64revtb[256] = {
  -3, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*0-15*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*16-31*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, /*32-47*/
  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -2, -1, -1, /*48-63*/
  -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, /*64-79*/
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, /*80-95*/
  -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, /*96-111*/
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, /*112-127*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*128-143*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*144-159*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*160-175*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*176-191*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*192-207*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*208-223*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*224-239*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1  /*240-255*/
};

static unsigned int raw_base64_decode(uint8_t *in,
                        uint8_t* out, int strict, int *err) {
    unsigned int  result = 0;
    int x = 0;
    unsigned char buf[3] = {0, 0, 0};
    unsigned char *p = in, pad = 0;

    *err = 0;
    while (!pad) {
        switch ((x = b64revtb[*p++])) {
            case -3: /* NULL TERMINATOR */
                if (((p - 1) - in) % 4) *err = 1;
                return result;
            case -2: /* PADDING CHARACTER. INVALID HERE */
                if (((p - 1) - in) % 4 < 2) {
                    *err = 1;
                    return result;
                } else if (((p - 1) - in) % 4 == 2) {
                    /* Make sure there's appropriate padding */
                    if (*p != '=') {
                        *err = 1;
                        return result;
                    }
                    buf[2] = 0;
                    pad = 2;
                    result++;
                    break;
                } else {
                    pad = 1;
                    result += 2;
                    break;
                }
                return result;
            case -1:
                if (strict) {
                    *err = 2;
                    return result;
                }
                break;
            default:
                switch (((p - 1) - in) % 4) {
                    case 0:
                        buf[0] = (unsigned char)(x << 2);
                        break;
                    case 1:
                        buf[0] |= (unsigned char)(x >> 4);
                        buf[1] = (unsigned char)(x << 4);
                        break;
                    case 2:
                        buf[1] |= (unsigned char)(x >> 2);
                        buf[2] = (unsigned char)(x << 6);
                        break;
                    case 3:
                        buf[2] |= (unsigned char)x;
                        result += 3;
                        for (x = 0;  x < 3 - pad;  x++) *out++ = buf[x];
                        break;
                }
                break;
        }
    }
    for (x = 0;  x < 3 - pad;  x++) *out++ = buf[x];
    return result;
}

void PEM_strip_header_and_footer(
               uint8_t *pem,
               size_t pem_len,
               uint8_t *stripped_pem,
               size_t *real_pem_len
        )
{
    int i = 0;
    int j = 0;
    int real_begin = 0;
    int real_end = 0;
    for (i = 0; i < (int)pem_len; i++)
    {
        if (pem[i] == '\n' || pem[i] == '\r') break;
    }
    real_begin = i+1; // the character right after \n

    // do not search \n from the exact end, 
    // which may contain one '\n' that we don't want
    // to strip the footer "---- END Public Key -----"
    for (i = (int)pem_len - 5; i >= 0; i--)
    {
        if (pem[i] == '\n' || pem[i] == '\r') break;
    }

    real_end = i;

    // remove carriage return if any
    for (i = real_begin, j = 0; i < real_end; i++)
    {
        if (pem[i] != '\n' && pem[i] != '\r')
        {
            stripped_pem[j] = pem[i];
            j++;
        }
    }
    *real_pem_len = j;
}

int PEM2DER_PublicKey_converter(const uint8_t *pem_pub, size_t pem_len, uint8_t *der, size_t *der_len)
{
    uint8_t *stripped_pk_pem = NULL;
    size_t stripped_len = 0;

    int temp_len = 0;
    int errorcode = 0;

    if (pem_pub == NULL || pem_len == 0)
        return 1;

    stripped_pk_pem = (uint8_t*)malloc(pem_len);
    if (stripped_pk_pem == NULL) return 1;
    memset(stripped_pk_pem, 0x00, pem_len);
    PEM_strip_header_and_footer((uint8_t*)pem_pub, pem_len, stripped_pk_pem, &stripped_len);

    if (stripped_len <= 0 || stripped_len > pem_len)
    {
        free(stripped_pk_pem);
        return 1;
    }
    temp_len = raw_base64_decode(stripped_pk_pem, der, 0, &errorcode);
    free(stripped_pk_pem);
    if (!errorcode)
    {
        *der_len = temp_len;
    }

    return errorcode;
}
