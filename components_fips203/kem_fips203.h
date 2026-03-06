/*
 * kem_fips203.h — FIPS 203 (ML-KEM) compliant KEM function declarations
 *
 * These functions implement the algorithmic corrections identified in
 * the FIPS 203 gap analysis (see sim/validation/fips203_gap_analysis.md).
 *
 * Changes from original kem.h:
 *   - keypair_fips203: accepts (d, z) as parameters per Alg 20
 *   - enc_fips203:     removes m<-H(m), returns K directly, adds modulus check
 *   - dec_fips203:     uses J(z||c) for implicit rejection, returns K' directly
 *
 * NOTE: These functions use the 90s symmetric primitives (SHA-256/SHA-512/AES)
 * which are NOT standardized in FIPS 203. They demonstrate the correct
 * algorithmic structure only.
 */

#ifndef KEM_FIPS203_H
#define KEM_FIPS203_H

#include <stdint.h>
#include "params.h"

/*
 * FIPS 203 Algorithm 20: ML-KEM.KeyGen_internal(d, z)
 * Deterministic key generation from seeds d and z.
 */
int crypto_kem_keypair_fips203(uint8_t *pk, uint8_t *sk,
                               const uint8_t d[KYBER_SYMBYTES],
                               const uint8_t z[KYBER_SYMBYTES]);

/*
 * FIPS 203 Algorithm 21: ML-KEM.Encaps_internal(ek, m)
 * Deterministic encapsulation from message m.
 * Includes modulus check on ek (GAP-4 fix).
 * Returns -1 if modulus check fails.
 */
int crypto_kem_enc_fips203(uint8_t *ct, uint8_t *ss,
                           const uint8_t *pk,
                           const uint8_t m[KYBER_SYMBYTES]);

/*
 * FIPS 203 Algorithm 22: ML-KEM.Decaps_internal(dk, c)
 * Uses K' directly on success, J(z||c) on failure.
 */
int crypto_kem_dec_fips203(uint8_t *ss,
                           const uint8_t *ct,
                           const uint8_t *sk);

/*
 * FIPS 203 Section 7.1: Modulus check on encapsulation key.
 * Verifies all decoded coefficients are in [0, q-1].
 * Returns 0 on success, -1 on failure.
 */
int mlkem_check_ek(const uint8_t *ek);

#endif /* KEM_FIPS203_H */
