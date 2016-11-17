#ifndef __XMR_CRYPTO_H__
#define __XMR_CRYPTO_H__

#include <cstddef>
#include "crypto-constants.h"

#pragma pack(push, 1)

typedef struct { uint8_t data[XMR_KEY_SIZE_BYTES]; } xmr_ec_point;
typedef struct { uint8_t data[XMR_KEY_SIZE_BYTES]; } xmr_ec_scalar;
typedef struct { xmr_ec_scalar c, r; } xmr_signature;
typedef struct { uint8_t data[XMR_HASH_SIZE]; } xmr_hash;

typedef xmr_ec_point xmr_public_key;
typedef xmr_ec_scalar xmr_secret_key;
typedef xmr_ec_point xmr_key_derivation;
typedef xmr_ec_point xmr_key_image;

#pragma pack(pop)

xmr_secret_key xmr_generate_keys(xmr_public_key *pub, xmr_secret_key *sec, const xmr_secret_key *rkey, bool recover);
bool xmr_check_key(const xmr_public_key *pub);
bool xmr_secret_key_to_public_key(const secret_key *sec, public_key *pub);
bool xmr_generate_key_derivation(const xmr_public_key *key1, const xmr_secret_key *key2, xmr_key_derivation *derivation);
void xmr_derivation_to_scalar(const xmr_key_derivation *derivation, size_t output_index, xmr_ec_scalar *res);
bool xmr_derive_public_key(const xmr_key_derivation *derivation, size_t output_index, const xmr_public_key *base, xmr_public_key *derived_key);
void xmr_derive_secret_key(const xmr_key_derivation *derivation, size_t output_index, const xmr_secret_key *base, xmr_secret_key *derived_key);
void xmr_generate_signature(const xmr_hash *prefix_hash, const xmr_public_key *pub, const xmr_secret_key *sec, xmr_signature *sig);
void xmr_generate_key_image(const xmr_public_key *pub, const xmr_secret_key *sec, xmr_key_image *image);
bool xmr_generate_ring_signature(const xmr_hash *prefix_hash, const xmr_key_image *image, const xmr_public_key *const *pubs, size_t pubs_count, const xmr_secret_key *sec, size_t sec_index, xmr_signature *sig);

#endif
