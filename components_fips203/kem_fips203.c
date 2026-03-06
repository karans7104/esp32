/*
 * kem_fips203.c — FIPS 203 (ML-KEM) compliant KEM functions
 *
 * Fixes applied:
 *   GAP-1: G(d || k) domain separation in KeyGen     [Alg 16 Step 1]
 *   GAP-2: Remove m <- H(m) pre-hash in Encaps       [Alg 20 Step 1]
 *   GAP-3: K direct (no KDF), J(z||c) for rejection  [Alg 20-22]
 *   GAP-4: Modulus check on encapsulation key         [Section 7.1]
 *
 * NOTE: Uses 90s symmetric primitives (SHA-256/SHA-512/AES) — not FIPS 203
 * compliant at the primitive level. Demonstrates algorithmic fixes only.
 * FIPS 203 requires SHA-3/SHAKE for full compliance (see GAP-6).
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "params.h"
#include "kem.h"
#include "indcpa.h"
#include "verify.h"
#include "symmetric.h"
#include "poly.h"
#include "polyvec.h"
#include "kem_fips203.h"

/* Forward declaration — defined in indcpa_fips203.c */
extern void indcpa_keypair_fips203(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                                   uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                                   const uint8_t d[KYBER_SYMBYTES]);

/*
 * GAP-4 FIX: Modulus check on encapsulation key.
 * FIPS 203 Section 7.1: verify all ByteDecode_12 coefficients are in [0, q-1].
 *
 * Returns 0 if all coefficients valid, -1 if any coefficient >= q.
 */
int mlkem_check_ek(const uint8_t *ek)
{
  unsigned int i, j;
  poly t;

  for(i = 0; i < KYBER_K; i++) {
    poly_frombytes(&t, ek + i * KYBER_POLYBYTES);
    for(j = 0; j < KYBER_N; j++) {
      if(t.coeffs[j] >= KYBER_Q)
        return -1;
    }
  }
  return 0;
}

/*
 * FIPS 203 Algorithm 20: ML-KEM.KeyGen_internal(d, z)
 *
 * GAP-1: Uses indcpa_keypair_fips203 which applies G(d || k) domain separation.
 * GAP-7: Accepts (d, z) as parameters for deterministic generation.
 *
 * Key layout: dk = dk_pke || ek || H(ek) || z
 */
int crypto_kem_keypair_fips203(uint8_t *pk, uint8_t *sk,
                               const uint8_t d[KYBER_SYMBYTES],
                               const uint8_t z[KYBER_SYMBYTES])
{
  size_t i;

  /* Step 1: (ek, dk_pke) <- K-PKE.KeyGen(d)  [with G(d||k) fix] */
  indcpa_keypair_fips203(pk, sk, d);

  /* Step 2: dk <- dk_pke || ek || H(ek) || z */
  for(i = 0; i < KYBER_INDCPA_PUBLICKEYBYTES; i++)
    sk[i + KYBER_INDCPA_SECRETKEYBYTES] = pk[i];

  /* H(ek) */
  hash_h(sk + KYBER_SECRETKEYBYTES - 2*KYBER_SYMBYTES,
         pk, KYBER_PUBLICKEYBYTES);

  /* z */
  memcpy(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, z, KYBER_SYMBYTES);

  return 0;
}

/*
 * FIPS 203 Algorithm 21: ML-KEM.Encaps_internal(ek, m)
 *
 * GAP-2 FIX: Removed m <- H(m) pre-hashing.
 * GAP-3 FIX: K = first 32 bytes of G(m || H(ek)), no KDF(K'||H(c)).
 * GAP-4 FIX: Modulus check on ek before use.
 *
 * Returns -1 if modulus check fails, 0 on success.
 */
int crypto_kem_enc_fips203(uint8_t *ct, uint8_t *ss,
                           const uint8_t *pk,
                           const uint8_t m[KYBER_SYMBYTES])
{
  uint8_t buf[2*KYBER_SYMBYTES];
  uint8_t kr[2*KYBER_SYMBYTES];

  /* GAP-4: Modulus check on encapsulation key */
  if(mlkem_check_ek(pk) != 0)
    return -1;

  /*
   * GAP-2 FIX: Use m directly — no hash_h(buf, buf, KYBER_SYMBYTES).
   * Original Kyber had m <- H(m) here; FIPS 203 removes this step.
   */
  memcpy(buf, m, KYBER_SYMBYTES);

  /* H(ek) — multitarget countermeasure */
  hash_h(buf + KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);

  /* (K, r) <- G(m || H(ek)) */
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  /* c <- K-PKE.Encrypt(ek, m, r) */
  indcpa_enc(ct, buf, pk, kr + KYBER_SYMBYTES);

  /*
   * GAP-3 FIX: K is used directly from G output.
   * Original Kyber computed KDF(K' || H(c)); FIPS 203 says K = kr[0:32].
   */
  memcpy(ss, kr, KYBER_SSBYTES);

  return 0;
}

/*
 * FIPS 203 Algorithm 22: ML-KEM.Decaps_internal(dk, c)
 *
 * GAP-3 FIX: K' used directly on success (no KDF).
 * GAP-3 FIX: K_bar = J(z || c) for implicit rejection (not KDF(z || H(c))).
 *
 * The J function is SHAKE-256 in FIPS 203; here we use the 90s kdf (SHA-256)
 * to demonstrate the algorithmic structure. The key difference is that J
 * operates on (z || c) — the full ciphertext — rather than (z || H(c)).
 */
int crypto_kem_dec_fips203(uint8_t *ss,
                           const uint8_t *ct,
                           const uint8_t *sk)
{
  size_t i;
  int fail;
  uint8_t buf[2*KYBER_SYMBYTES];
  uint8_t kr[2*KYBER_SYMBYTES];
  uint8_t cmp[KYBER_CIPHERTEXTBYTES];
  const uint8_t *pk = sk + KYBER_INDCPA_SECRETKEYBYTES;

  /* Step 1: m' <- K-PKE.Decrypt(dk_pke, c) */
  indcpa_dec(buf, ct, sk);

  /* Step 2: Append h = H(ek) from stored dk */
  for(i = 0; i < KYBER_SYMBYTES; i++)
    buf[KYBER_SYMBYTES + i] = sk[KYBER_SECRETKEYBYTES - 2*KYBER_SYMBYTES + i];

  /* Step 3: (K', r') <- G(m' || h) */
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  /* Step 4: c' <- K-PKE.Encrypt(ek, m', r') */
  indcpa_enc(cmp, buf, pk, kr + KYBER_SYMBYTES);

  /* Step 5: Compare c and c' (constant time) */
  fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

  /*
   * GAP-3 FIX: Implicit rejection and shared secret derivation.
   *
   * FIPS 203 Algorithm 22:
   *   K_bar <- J(z || c)     -- rejection value from full ciphertext
   *   if c != c': return K_bar
   *   return K'              -- direct, no KDF
   *
   * Original Kyber:
   *   cmov(kr, z, 32, fail)
   *   kr[32:64] <- H(c)
   *   K <- KDF(kr[0:32] || kr[32:64])
   *
   * We compute K_bar = J(z || c) into ss first, then conditionally
   * overwrite with K' if verification succeeded (constant time).
   */
  {
    /* Compute K_bar = J(z || c) */
    uint8_t j_input[KYBER_SYMBYTES + KYBER_CIPHERTEXTBYTES];
    memcpy(j_input, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES);
    memcpy(j_input + KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
    kdf(ss, j_input, KYBER_SYMBYTES + KYBER_CIPHERTEXTBYTES);
  }

  /* Constant-time select: if success (fail==0), overwrite ss with K' */
  cmov(ss, kr, KYBER_SSBYTES, (uint8_t)(1 - fail));

  return 0;
}
