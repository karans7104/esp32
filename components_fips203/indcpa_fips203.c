/*
 * indcpa_fips203.c — FIPS 203 compliant K-PKE.KeyGen
 *
 * Fixes GAP-1: Adds domain separation byte k to G input.
 *   Original: (rho, sigma) <- G(d)          [32-byte input]
 *   FIPS 203: (rho, sigma) <- G(d || k)     [33-byte input]
 *   Reference: FIPS 203 Algorithm 16 (K-PKE.KeyGen), Step 1
 *
 * NOTE: Uses 90s primitives (hash_g = SHA-512) — not FIPS 203 compliant
 * at the primitive level. Demonstrates algorithmic fix only.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "params.h"
#include "polyvec.h"
#include "poly.h"
#include "ntt.h"
#include "symmetric.h"

/* gen_matrix is non-static in indcpa.c, declared in indcpa.h */
#include "indcpa.h"

/*
 * FIPS 203 Algorithm 16: K-PKE.KeyGen(d)
 *
 * Unlike the original indcpa_keypair which generates d internally,
 * this function accepts d as a parameter (matching the FIPS 203
 * internal function API) and appends the domain separation byte.
 */
void indcpa_keypair_fips203(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                            uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                            const uint8_t d[KYBER_SYMBYTES])
{
  unsigned int i;
  /*
   * GAP-1 FIX: buf is 2*KYBER_SYMBYTES + 1 to hold G output (64 bytes)
   * with room for the 33-byte input (d || k).
   * We use a separate input buffer to avoid aliasing.
   */
  uint8_t buf[2*KYBER_SYMBYTES];
  uint8_t g_input[KYBER_SYMBYTES + 1];  /* d || k */
  const uint8_t *publicseed = buf;
  const uint8_t *noiseseed = buf + KYBER_SYMBYTES;
  uint8_t nonce = 0;
  polyvec a[KYBER_K], e, pkpv, skpv;

  /* FIPS 203 Alg 16 Step 1: (rho, sigma) <- G(d || k) */
  memcpy(g_input, d, KYBER_SYMBYTES);
  g_input[KYBER_SYMBYTES] = (uint8_t)KYBER_K;  /* domain separation byte */
  hash_g(buf, g_input, KYBER_SYMBYTES + 1);

  gen_matrix(a, publicseed, 0);  /* gen_a */

  for(i = 0; i < KYBER_K; i++)
    poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);
  for(i = 0; i < KYBER_K; i++)
    poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);

  polyvec_ntt(&skpv);
  polyvec_ntt(&e);

  for(i = 0; i < KYBER_K; i++) {
    polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
    poly_tomont(&pkpv.vec[i]);
  }

  polyvec_add(&pkpv, &pkpv, &e);
  polyvec_reduce(&pkpv);

  /* pack_sk: polyvec_tobytes */
  polyvec_tobytes(sk, &skpv);

  /* pack_pk: polyvec_tobytes + seed */
  polyvec_tobytes(pk, &pkpv);
  memcpy(pk + KYBER_POLYVECBYTES, publicseed, KYBER_SYMBYTES);
}
