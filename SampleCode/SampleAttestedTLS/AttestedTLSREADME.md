# Secure Channel in Intel SGX SDK

  As Intel SGX SDK is getting adopted into more realistic scenarios, we are receiving requests from Intel SGX SDK developers for adding secure channel support.

  We do have the attestation sample that shows how to conduct remote attestation between two enclaves and establish a `proprietary` channel based on asymmetric keys exchanged during the attestation process. It demonstrates how to conduct mutual attestation but it does not go all the way to show how to establish a fully secure channel.

  Most of the real world software uses TLS-like standard protocol through popular TLS APIs (currently OpenSSL) for establishing secure channels. Thus, instead of inventing a new communication protocol, we implemented `Attested TLS` feature to address above customer need by adding a set of new Intel SGX SDK APIs to help seamlessly integrate remote attestation into the popular TLS protocol for establishing an TLS channel with attested connecting party without modifying existing TLS APIs (currently supported OpenSSL inside SGX enclave).

# What is an Attested TLS channel

The remote attestation feature that comes with Intel SGX could significantly improve a TLS endpoint's (client or server) trustworthiness for a TLS connection starting or terminating inside an enclave. An Attested TLS channel is a TLS channel that integrates remote attestation validation as part of the TLS channel establishing process. Once established, it guarantees that an attested connecting party is running inside a TEE with expected identity.

There are two types of Attested TLS connections:
1. Both ends of an Attested TLS channel terminate inside SGX enclaves
    - Guarantee that both parties of a TLS channel are running inside SGX enclaves
    - Intel SGX SDK sample: SampleAttestedTLS\client
2. Only one end of an Attested TLS channel terminate inside SGX enclaves
    - In this case, the assumption is that the end not terminated inside an SGX encalve is a trust party. The most common use case is, this non-enclave party might have secrets to securely share with the other party through an Attested TLS channel.
    - Intel SGX SDK sample: SampleAttestedTLS\non_enc_client

## Prerequisites

  The audience is assumed to be familiar with:

  - [Transport Layer Security (TLS)](https://en.wikipedia.org/wiki/Transport_Layer_Security) a cryptographic protocol designed to provide communications security over a computer network.

  - [SGX Enclave Attestation](https://software.intel.com/content/www/us/en/develop/topics/software-guard-extensions/attestation-services.html?wapkw=Intel%20SGX%20attestation): Attestation is the concept of a HW entity or of a combination of HW and SW gaining the trust of a remote provider or producer.

### How it works

  By taking advantage of the fact that TLS involving parties use public-key cryptography for identity authentication during the [TLS handshaking process](https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_handshake), the Attested TLS feature uses a self-signed X509.V3 certificate to represent a TLS endpoint's identity. We make this certificate cryptographically bound to this specific enclave instance by adding a custom certificate extension (called quote extension) with this enclave's attestation quote that has the certificate's public key information embedded.

  A new API tee_get_attestation_certificate_with_evidence was added for generating such a self-signed certificate for use in the TLS handshaking process

#### Generate TLS certificate

  A connecting party needs to provide a key pair for the tee_get_certificate_with_evidence api to produce a self-signed certificate. These keys could be transient keys and unique for each new TLS connection.
  - a private key (pkey): used for generating a certificate and represent the identity of the TLS connecting party
  - a public key (pubkey): used in the TLS handshake process to create a digital signature in every TLS connection,

```
/**
 * tee_get_certificate_with_evidence
 *
 * This function generates a self-signed x.509 certificate with embedded
 * evidence generated for the enclave.
 * This function only runs inside enclave
 *
 *
 * @param[in] subject_name a string containing an X.509 distinguished
 * name (DN) for customizing the generated certificate. This name is also used
 * as the issuer name because this is a self-signed certificate
 * See RFC5280 (https://tools.ietf.org/html/rfc5280) for details
 * Example value "CN=Intel SGX Enclave,O=Intel Corporation,C=US"
 *
 * @param[in] p_prv_key A private key used to sign this certificate
 * @param[in] private_key_size The size of the private_key in bytes
 * @param[in] p_pub_key A public key used as the certificate's subject key
 * @param[in] public_key_size The size of the public key in bytes
 * @param[out] pp_output_cert A pointer to output certificate pointer
 * @param[out] p_output_cert_size A pointer to the size of the output certificate above
 *
 * @return SGX_QL_SUCCESS on success
 */
quote3_error_t SGXAPI tee_get_certificate_with_evidence(
    const unsigned char *p_subject_name,
    const uint8_t *p_prv_key,
    size_t private_key_size,
    const uint8_t *p_pub_key,
    size_t public_key_size,
    uint8_t **pp_output_cert,
    size_t *p_output_cert_size);

```
#### Authenticate peer certificate

Upon receiving a certificate from the peer endpoint, a connecting party needs to perform peer certificate validation.

In this feature, instead of using the TLS API's default authentication routine, which validates the certificate against a pre-determined CAs for authentication, an application needs to conduct "Extended custom certificate validation" inside the peer custom certificate verification callback (cert_verify_callback), which is supported by all the popular TLS APIs.

```
For example:
    OpenSSL:
            void SSL_CTX_set_verify(
                      SSL_CTX *ctx, int mode,
                      int (*verify_callback)(int, X509_STORE_CTX *))
```
##### Custom extended certificate validation

The following four validation steps are performed inside the cert_verify_callback
  1. Validate certificate
     - Verify the signature of the self-signed certificate to ascertain that the attestation evidence is genuine and unmodified.
  2. Validate the evidence
     - Extract this evidence extension from the certificate
     - Perform evidence validation
  3. Validate peer enclave's identity
     - Validate the enclave’s identity (e.g., MRENCLAVE in SGX) against the expected list. This check ensures only the intended party is allowed to connect to.

  A new SGX API, tee_verify_certificate_with_evidence_host() or tee_verify_ceritificate_with_evidence() for inside enclave calls, was added to perform step 1-2 and leaving step 3 to application for business logic.

  A caller wants to fail cert_verify_callback with non-zero code if either certificate signature validation failed or unexpected TEE identity was found. This failure return will cause the TLS handshaking process to terminate immediately, thus preventing establishing connection with an unqualified connecting party.

```
/**
 * tee_verify_certificate_with_evidence_host for outside enclave calls
 * tee_verify_certificate_with_evidence for inside enclave calls
 *
 * This function performs SGX quote and X.509 certificate verification. The
 * validation includes extracting SGX quote extension from the
 * certificate before validating the quote
 *
 * @param[in] p_cert_in_der A pointer to buffer holding certificate contents
 *  in DER format
 * @param[in] cert_in_der_len The size of certificate buffer above
 * @param[in] expiration_check_date The date that verifier will use to determine if any of the inputted collateral have expired
 * @param[out] p_qv_result SGX quote verification result
 * @param[out] pp_supplemental_data A pointer to SGX quote verification
 *             supplemental data pointer
 * @param[out] p_supplemental_data_size The size of supplemental data above
 *
 * @retval SGX_SUCCESS on a successful validation
 * @retval SGX_QUOTE_VERIFY_FAILURE on quote verification failure
 * @retval SGX_QUOTE_VERIFY_WARNING on quote verification failed with non-critical
 *         error, pls refer to output parameters 'p_qv_result' and
 *         'p_supplemental_data' to customize your own verification policy
 * @retval SGX_ERROR_INVALID_PARAMETER At least one parameter is invalid
 * @retval SGX_ERROR_UNEXPECTED general failure
 */
#if INSIDE_ENCLAVE
 quote3_error_t SGXAPI tee_verify_certificate_with_evidence(
#else OUTSIDE_ENCLAVE_CALL
 quote3_error_t SGXAPI tee_verify_certificate_with_evidence_host(
#endif
    const uint8_t *p_cert_in_der,
    size_t cert_in_der_len,
    const time_t expiration_check_date,
    sgx_ql_qv_result_t *p_qv_result,
    uint8_t **pp_supplemental_data,
    uint32_t *p_supplemental_data_size);
```
   Once the received certificate passed above validation, the TLS handshaking process can continue until an connection is established. Once connected, a connecting party can be confident that the other connecting party is indeed a specific enclave image running inside the enclave.

In the case of establishing a Attested TLS channel between two enclaves, the same authentication process could be applied to both directions in the TLS handshaking process to establish an mutually attested TLS channel between two enclaves.

 Please see OE SDK samples for how to use those new APIs along with your favorite TLS library.
