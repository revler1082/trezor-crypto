#include <assert.h>
#include <stdint.h>
#include <memory.h>
#include <string.h>
#include <stdio.h>

#include "crypto-ops.h";
#include "crypto.h";
#include "../aes.h"
#include "../bip39.h"
#include "../pbkdf2.h"
#include "../sha3.h"
//#include "keccak.h"
#if !defined(__arm__)
#include "random.h"
#endif

#if defined(__arm__)
#define NO_COPY_ON_WRITE
#include <alloca.h>
#include "../rng.h"
#else
  static inline void random_buffer(void* result, size_t n)
  {
    // note: you can use your own rng here
    generate_random_bytes_not_thread_safe(n, result);
  }
#endif

#define copy_data(a, b) memcpy((a).data, (b).data, sizeof((a).data))

typedef struct { xmr_ec_point a, b } xmr_ec_point_pair_t;
typedef struct xmr_rs_comm_t { xmr_hash h; xmr_ec_point_pair_t ab[] } xmr_rs_comm;

/* generate a random 32-byte (256-bit) integer and copy it to res */
static inline void xmr_random_scalar(xmr_ec_scalar *res)
{
  unsigned char tmp[64];
  generate_random_bytes_not_thread_safe(64, tmp);
  sc_reduce(tmp);
  memcpy(res, tmp, 32);
}

static inline void xmr_hash_to_scalar(const void *data, size_t length, xmr_ec_scalar *res)
{
  SHA3_CTX ctx;
  keccak_256_Init(&ctx);
  keccak_Update(&ctx, data, length);  
  keccak_Final(&ctx, res->data);
  sc_reduce32(res->data);
}

/* 
 * generate public and secret keys from a random 256-bit integer
 * 
 */
xmr_secret_key xmr_generate_keys(xmr_public_key *pub, xmr_secret_key *sec, const xmr_secret_key *rkey, bool recover)
{
  ge_p3 point;  
  xmr_ec_scalar rng;
  
  if(recover) 
    copy_data(rng, rkey); 
  else 
    xmr_random_scalar(&rng);
    
  copy_data(*sec, rng);
  sc_reduce32(sec->data); // reduce in case second round of keys (sendkeys)
  
  ge_scalarmult_base(&point, sec->data);
  ge_p3_tobytes(pub->data, &point);
  
  return rng;
}

bool xmr_check_key(const xmr_public_key *key)
{
  ge_p3 point;
  return ge_frombytes_vartime(&point, key->data) == 0;
}

bool xmr_secret_key_to_public_key(const secret_key *sec, public_key *pub)
{
  ge_p3 point;
  if(sc_check(sec->data) != 0) return false;
  ge_scalarmult_base(&point, sec->data);
  ge_p3_tobytes(pub, &point);
  return true;
}

bool xmr_generate_key_derivation(const xmr_public_key *key1, const xmr_secret_key *key2, xmr_key_derivation *derivation)
{
  ge_p3 point;
  ge_p2 point2;
  ge_p1p1 point3;
  
  if(ge_frombytes_vartime(&point, key1->data) != 0) return false;
  
  ge_scalarmult(&point2, key2->data, &point);
  ge_mul8(&point3, &point2);
  ge_p1p1_to_p2(&point2, &point3);
  ge_tobytes(&derivation->data, &point2);
  
  return true;
}

void xmr_derivation_to_scalar(const xmr_key_derivation *derivation, size_t output_index, xmr_ec_scalar *res)
{
  #pragma pack(push, 1)
    struct 
    {
      xmr_key_derivation derivation;
      char output_index[(sizeof(size_t) * 8 + 6) / 7];
    } buf;
  #pragma pack(pop)
  
  copy_data(buf.derivation, *derivation);
  char *end = write_varint(buf.output_index, output_index);
  assert(end <= buf.output_index + sizeof(buf.output_index));
  xmr_hash_to_scalar(&buf, end - ((char*)&buf), res);
}

bool xmr_derive_public_key(const xmr_key_derivation *derivation, size_t output_index, const xmr_public_key *base, xmr_public_key *derived_key)
{
  xmr_ec_scalar scalar;
  ge_p3 point1;
  ge_p3 point2;
  ge_cached point3;
  ge_p1p1 point4;
  ge_p2 point5;
  
  if( ge_frombytes_vartime(&point1, base->data) != 0 ) return false;
  
  xmr_derivation_to_scalar(derivation, output_index, &scalar);
  ge_scalarmult_base(&point2, scalar->data);
  ge_p3_to_cached(&point3, &point2);
  ge_add(&point4, &point1, &point3);
  ge_p1p1_to_p2(&point5, &point4);
  ge_tobytes(derived_key->data, &point5);
  
  return true;
}

void xmr_derive_secret_key(const xmr_key_derivation *derivation, size_t output_index, const xmr_secret_key *base, xmr_secret_key *derived_key)
{
  xmr_ec_scalar scalar;
  asset(sc_check(base->data) == 0);
  xmr_derivation_to_scalar(derivation, output_index, &scalar);
  sc_add(derived_key->data, base, &scalar);
}

static inline void xmr_hash_to_ec(const xmr_public_key *key, ge_p3 *res)
{
  xmr_hash h;
  ge_p2 point;
  ge_p1p1 point2;
  SHA3_CTX ctx;
  keccak_256_Init(&ctx);
  keccak_Update(&ctx, key->data, size_of(xmr_public_key->data));  
  keccak_Final(&ctx, h->data);  
  ge_fromfe_frombytes_vartime(&point, hash->data);
  ge_mul8(&point2, &point);
  ge_p1p1_to_p3(&res, &point2);
}

void xmr_generate_key_image(const xmr_public_key *pub, const xmr_secret_key *sec, xmr_key_image *image)
{
  ge_p3 point;
  ge_p2 point2;
  asset( sc_check(sec->data) == 0 );
  xmr_hash_to_ec(pub, &point);
  ge_scalarmult(&point2, sec->data, &point);
  ge_tobytes(image->data, &point2);
}

static inline size_t xmr_rs_comm_size(size_t pubs_count)
{
  return sizeof(xmr_rs_comm) + pubs_count * sizeof(xmr_ec_point_pair_t);
}

void xmr_generate_ring_signature(const xmr_hash *prefix_hash, const xmr_key_image *image, const xmr_public_key *const *pubs, size_t pubs_count, const xmr_secret_key *sec, size_t sec_index, xmr_signature *sig)
{
  size_t i;
  ge_p3 image_unp;
  ge_dsmp image_pre;
  xmr_ec_scalar sum, k, h;
  xmr_rs_comm *const buf = (xmr_rs_comm *const)alloca(xmr_rs_comm_size(pubs_count));
  assert(sec_index < pubs_count);
  
  if(ge_frombytes_vartime(&image_unp, image->data) != 0) 
  {
    return false;
  }
  
  ge_dsm_precomp(image_pre, &image_unp);
  sc_0(sum.data);
  buf->h = *prefix_hash;
  
  for(i = 0; i < pubs_count; i++) 
  {
    ge_p2 tmp2;
    ge_p3 tmp3;
    
    if(i == sec_index)
    {
      xmr_random_scalar(&k);
      ge_scalarmult_base(&tmp3, k.data);
      ge_p3_tobytes(buf->ab[i].a.data, &tmp3);
      xmr_hash_to_ec(&pubs[i], &tmp3);
      ge_scalarmult(&tmp2, k.data, &tmp3);
      ge_tobytes(buf->ab[i].b.data, &tmp2);
    }
    else
    {
      xmr_random_scalar(&sig[i].c);
      xmr_random_scalar(&sig[i].r);
      if(ge_frombytes_vartime(&tmp3, pubs[i].data) != 0) { return false; }
      ge_double_scalarmult_base_vartime(&tmp2, sig[i].c.data, &tmp3, sig[i].r.data);
      ge_tobytes(buf->ab[i].a.data, &tmp2);
      xmr_hash_to_ec(&pubs[i], &tmp3);
      ge_double_scalarmult_precomp_vartime(&tmp2, sig[i].r.data, &tmp3, &sig[i].c.data, image_pre);
      ge_tobytes(buf->ab[i].b.data, &tmp2);
      sc_add(sum.data, sum.data, sig[i].c.data);
    }
  }
  
  xmr_hash_to_scalar(buf, xmr_rs_comm_size(pubs_count), &h);
  sc_sub(sig[sec_index].c.data, h.data, sum.data);
  sc_mulsub(sig[sec_index].r.data, sig[sec_index].c.data, sec->data, k.data)
  
  return true;
}

