#include <mbedtls_hkdf.h>
#include <mbedtls/hkdf.h>

namespace nos::crypto
{

static int mbedtls_hkdf_hmac(const mbedtls_md_info_t *md,
                             crypto_context_buffer *salt,
                             crypto_symmetric_key *ikm,
                             crypto_context_buffer *ctx,
                             crypto_symmetric_key *okm)
{
    return mbedtls_hkdf(md,
                        salt->context, salt->context_len,
                        ikm->key, ikm->key_len,
                        ctx->context, ctx->context_len,
                        okm->key, okm->key_len);
}

int mbedtls_hkdf_intf::hkdf_hmac_sha256(crypto_context_buffer *salt,
                                        crypto_symmetric_key *ikm,
                                        crypto_context_buffer *ctx,
                                        crypto_symmetric_key *okm)
{
    return mbedtls_hkdf_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                             salt, ikm, ctx, okm);
}

int mbedtls_hkdf_intf::hkdf_hmac_sha384(crypto_context_buffer *salt,
                                        crypto_symmetric_key *ikm,
                                        crypto_context_buffer *ctx,
                                        crypto_symmetric_key *okm)
{
    return mbedtls_hkdf_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA384),
                             salt, ikm, ctx, okm);
}

int mbedtls_hkdf_intf::hkdf_hmac_sha512(crypto_context_buffer *salt,
                                        crypto_symmetric_key *ikm,
                                        crypto_context_buffer *ctx,
                                        crypto_symmetric_key *okm)
{
    return mbedtls_hkdf_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512),
                             salt, ikm, ctx, okm);
}

}
