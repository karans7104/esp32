# FIPS 203 Compliance Gap Analysis

## Kyber-512/768/1024 (90s variant) vs. NIST FIPS 203 (ML-KEM)

**Date:** March 2026  
**Standard Reference:** NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard (August 2024)  
**Implementation Under Audit:** `components/` directory — CRYSTALS-Kyber 90s reference (Segatz et al. 2022 dual-core ESP32 variant)

---

## Executive Summary

This analysis compares the existing CRYSTALS-Kyber 90s implementation against the finalized
FIPS 203 (ML-KEM) standard. Nine compliance gaps were identified across four severity levels:
**3 Critical** (algorithmic), **3 Moderate** (validation/primitive), **2 Minor** (naming/API),
and **1 Informational**. The critical gaps produce different shared secret values from identical
inputs, meaning this implementation is **not interoperable** with FIPS 203 ML-KEM.

Partial fixes are provided in `components_fips203/` demonstrating the required algorithmic
changes while retaining the 90s symmetric primitives (which are themselves non-compliant).

---

## Parameter Verification

| Parameter | Implementation (`params.h`) | FIPS 203 Table 2 | Status |
|-----------|----------------------------|-------------------|--------|
| n         | `KYBER_N = 256`            | 256               | PASS   |
| q         | `KYBER_Q = 3329`           | 3329              | PASS   |
| k (ML-KEM-512)  | `KYBER_K = 2`       | 2                 | PASS   |
| k (ML-KEM-768)  | `KYBER_K = 3`       | 3                 | PASS   |
| k (ML-KEM-1024) | `KYBER_K = 4`       | 4                 | PASS   |
| eta1 (k=2)| `KYBER_ETA1 = 3`          | 3                 | PASS   |
| eta1 (k=3,4)| `KYBER_ETA1 = 2`        | 2                 | PASS   |
| eta2      | `KYBER_ETA2 = 2`           | 2                 | PASS   |
| du (k=2,3)| `POLYVECCOMPRESSEDBYTES = K*320` (10 bits) | 10   | PASS   |
| du (k=4)  | `POLYVECCOMPRESSEDBYTES = K*352` (11 bits) | 11   | PASS   |
| dv (k=2,3)| `POLYCOMPRESSEDBYTES = 128` (4 bits) | 4         | PASS   |
| dv (k=4)  | `POLYCOMPRESSEDBYTES = 160` (5 bits) | 5         | PASS   |
| SYMBYTES  | 32                         | 32                | PASS   |
| SSBYTES   | 32                         | 32                | PASS   |

All lattice and compression parameters match FIPS 203 Table 2.

---

## NTT Verification

| Property | Implementation (`ntt.c`) | FIPS 203 Alg 9-10 | Status |
|----------|--------------------------|---------------------|--------|
| Root of unity | zeta = 17 | zeta = 17 | PASS |
| Modular arithmetic | Montgomery reduction | Allowed | PASS |
| Forward NTT structure | Iterative Cooley-Tukey butterfly | Matches Alg 9 | PASS |
| Inverse NTT structure | Iterative Gentleman-Sande butterfly | Matches Alg 10 | PASS |
| Scaling factor f | 1441 (= 128^-1 * 2^16 mod q) | 3303 (= 128^-1 mod q) | PASS (Montgomery form) |
| Zetas table | 128 precomputed values | Matches bit-reversed order | PASS |
| Base multiplication | `basemul()` with zeta | Matches `BaseCaseMultiply` | PASS |

The NTT implementation is mathematically equivalent to FIPS 203 Algorithms 9-10.

---

## Gap Analysis

### GAP-1: Missing Domain Separation in K-PKE.KeyGen [CRITICAL]

**FIPS 203 Reference:** Algorithm 13 (K-PKE.KeyGen), Step 1  
**Severity:** Critical — produces different key material from same seed

**FIPS 203 specifies:**
```
(rho, sigma) <- G(d || k)
```
where `d` is 32 random bytes and `k` is the single-byte ML-KEM parameter (2, 3, or 4).

**Current implementation** (`indcpa.c`, `indcpa_keypair`):
```c
esp_randombytes(buf, KYBER_SYMBYTES);     // d <- random(32)
hash_g(buf, buf, KYBER_SYMBYTES);         // G(d) — 32-byte input
```

**Gap:** The input to G is 32 bytes (`d` only). FIPS 203 requires 33 bytes (`d || k`).
The domain separation byte `k` prevents cross-parameter-set attacks and ensures that
the same seed `d` produces different keys for ML-KEM-512 vs ML-KEM-768 vs ML-KEM-1024.

**Fix:** Append `KYBER_K` as a single byte before calling `hash_g`:
```c
uint8_t buf[2*KYBER_SYMBYTES + 1];
esp_randombytes(buf, KYBER_SYMBYTES);
buf[KYBER_SYMBYTES] = KYBER_K;
hash_g(buf, buf, KYBER_SYMBYTES + 1);
```

---

### GAP-2: Unnecessary m <- H(m) Pre-Hashing in Encapsulation [CRITICAL]

**FIPS 203 Reference:** Algorithm 17 (ML-KEM.Encaps_internal), Step 1  
**Severity:** Critical — produces different shared secret from same randomness

**FIPS 203 specifies:**
```
(K, r) <- G(m || H(ek))
```
where `m` is used directly as sampled.

**Current implementation** (`kem.c`, `crypto_kem_enc`):
```c
esp_randombytes(buf, KYBER_SYMBYTES);
hash_h(buf, buf, KYBER_SYMBYTES);          // m <- H(m) — NOT IN FIPS 203
hash_h(buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
hash_g(kr, buf, 2*KYBER_SYMBYTES);
```

**Gap:** The `hash_h(buf, buf, KYBER_SYMBYTES)` line pre-hashes `m` before using it.
FIPS 203 removed this step that existed in the 2022 Kyber specification. The pre-hash
was a defense against poor RNG output, but FIPS 203 trusts the RNG (Section 3.3).

**Fix:** Remove the `hash_h(buf, buf, KYBER_SYMBYTES)` line.

---

### GAP-3: Shared Secret Derivation via KDF(K' || H(c)) [CRITICAL]

**FIPS 203 Reference:** Algorithms 17-18 (ML-KEM.Encaps_internal and ML-KEM.Decaps_internal)  
**Severity:** Critical — produces different shared secret value

**FIPS 203 specifies (Encaps):**
```
(K, r) <- G(m || H(ek))
return (K, c)                              // K is used directly
```

**FIPS 203 specifies (Decaps):**
```
(K', r') <- G(m' || h)
K_bar    <- J(z || c)                      // implicit rejection value
if c != c': return K_bar
return K'                                  // K' is used directly
```

**Current implementation (Encaps)** (`kem.c`, `crypto_kem_enc`):
```c
hash_g(kr, buf, 2*KYBER_SYMBYTES);         // (K', r) <- G(m || H(ek))
indcpa_enc(ct, buf, pk, kr+KYBER_SYMBYTES);
hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);  // overwrite r with H(c)
kdf(ss, kr, 2*KYBER_SYMBYTES);             // K <- KDF(K' || H(c))
```

**Current implementation (Decaps)** (`kem.c`, `crypto_kem_dec`):
```c
hash_g(kr, buf, 2*KYBER_SYMBYTES);
indcpa_enc(cmp, buf, pk, kr+KYBER_SYMBYTES);
fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);
hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
cmov(kr, sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES, fail);
kdf(ss, kr, 2*KYBER_SYMBYTES);             // K <- KDF(K'/z || H(c))
```

**Gap (Encaps):** FIPS 203 uses `K` directly (first 32 bytes of `G` output). The current
code applies an additional `KDF(K' || H(c))` step, incorporating the ciphertext hash.

**Gap (Decaps):** Two sub-gaps:
1. The implicit rejection value should be `J(z || c)` — the J function applied to `z`
   concatenated with the **full ciphertext** (not `H(c)`).
2. The final shared secret should be `K'` directly (not `KDF(K' || H(c))`).

**Fix (Encaps):** Replace the last three lines with:
```c
memcpy(ss, kr, KYBER_SSBYTES);             // K = first 32 bytes of G output
```

**Fix (Decaps):** Replace the implicit rejection and KDF with:
```c
// Compute implicit rejection: K_bar = J(z || c)
uint8_t j_input[KYBER_SYMBYTES + KYBER_CIPHERTEXTBYTES];
memcpy(j_input, sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES);
memcpy(j_input+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
kdf(ss, j_input, KYBER_SYMBYTES + KYBER_CIPHERTEXTBYTES);  // K_bar = J(z||c)

// Select K' on success, K_bar on failure (constant time)
cmov(ss, kr, KYBER_SSBYTES, 1-fail);       // if success, overwrite with K'
```

---

### GAP-4: Missing Encapsulation Key Modulus Check [MODERATE]

**FIPS 203 Reference:** Section 7.1, Algorithm 20 (ML-KEM.Encaps), Step 2  
**Severity:** Moderate — could accept malformed public keys

**FIPS 203 specifies:**
> "Perform the modulus check described in Section 7.2 on ek. If it fails, return ⊥."

The modulus check verifies that every coefficient decoded from the encapsulation key
via `ByteDecode_12` lies in the range `[0, q-1]` (i.e., `[0, 3328]`).

**Current implementation:**
```c
// poly_frombytes (poly.c) — decodes 12-bit values:
r->coeffs[2*i]   = ((a[3*i+0] >> 0) | ((uint16_t)a[3*i+1] << 8)) & 0xFFF;
r->coeffs[2*i+1] = ((a[3*i+1] >> 4) | ((uint16_t)a[3*i+2] << 4)) & 0xFFF;
```

**Gap:** The `& 0xFFF` mask produces values in `[0, 4095]`. Values in `[3329, 4095]`
are invalid but are silently accepted. No check is performed after decoding.

**Fix:** Add a modulus check function:
```c
int mlkem_check_pk(const uint8_t *pk) {
    polyvec t;
    for (unsigned int i = 0; i < KYBER_K; i++) {
        poly_frombytes(&t.vec[i], pk + i * KYBER_POLYBYTES);
        for (unsigned int j = 0; j < KYBER_N; j++) {
            if (t.vec[i].coeffs[j] >= KYBER_Q) return -1;
        }
    }
    return 0;
}
```

---

### GAP-5: Missing Input Length/Type Validation [MODERATE]

**FIPS 203 Reference:** Section 7.1 Step 1, Section 7.2 Step 1  
**Severity:** Moderate — no bounds checking on KEM inputs

**FIPS 203 specifies:**
> "Perform the type check on ek" (Encaps)  
> "Perform the type check on c and dk" (Decaps)

The type check verifies that inputs have the expected byte lengths before processing.

**Current implementation:** No explicit length validation. Functions accept raw pointers
with no size verification. Callers are trusted to provide correctly-sized buffers.

**Gap:** While the C API uses fixed-size array parameters (e.g., `uint8_t pk[KYBER_PUBLICKEYBYTES]`),
these degrade to pointers and provide no runtime enforcement. A compliant implementation
should validate input lengths at the API boundary.

**Fix:** Add length-checked wrapper functions that verify buffer sizes before
delegating to the core implementation.

---

### GAP-6: 90s Symmetric Primitives Not Standardized [MODERATE]

**FIPS 203 Reference:** Section 4.1 (Underlying Functions)  
**Severity:** Moderate — fundamental primitive mismatch

**FIPS 203 specifies:**

| Function | FIPS 203 Primitive |
|----------|-------------------|
| H        | SHA3-256          |
| G        | SHA3-512          |
| J        | SHAKE-256         |
| XOF      | SHAKE-128         |
| PRF      | SHAKE-256         |

**Current implementation** (`symmetric.h`, `KYBER_90S` defined):

| Function | Implementation Primitive |
|----------|------------------------|
| hash_h   | SHA-256               |
| hash_g   | SHA-512               |
| kdf      | SHA-256               |
| xof      | AES-256-CTR           |
| prf      | AES-256-CTR           |

**Gap:** The 90s variant uses AES-256-CTR and SHA-2 instead of SHAKE/SHA-3.
FIPS 203 does **not** standardize a 90s variant. The 90s variant existed only
in the pre-standardization Kyber specification for performance comparison.

**Impact:** Even with all algorithmic fixes applied, this implementation cannot
produce FIPS 203-compliant output because the underlying hash functions differ.
The fixes in `components_fips203/` demonstrate the correct algorithmic structure
while acknowledging this primitive-level limitation.

---

### GAP-7: Keypair Generates d Internally [MINOR]

**FIPS 203 Reference:** Algorithm 16 (ML-KEM.KeyGen_internal)  
**Severity:** Minor — API structure difference

**FIPS 203 specifies:**
```
ML-KEM.KeyGen_internal(d, z):
  (ek, dk_pke) <- K-PKE.KeyGen(d)
  dk <- (dk_pke || ek || H(ek) || z)
```

Both `d` and `z` are parameters to the internal function (sampled by the
external `ML-KEM.KeyGen` wrapper).

**Current implementation:** `indcpa_keypair` generates `d` internally via
`esp_randombytes`. `crypto_kem_keypair` generates `z` independently.

**Gap:** The seed `d` is not exposed as a parameter, preventing deterministic
testing and KAT vector verification. The functional behavior is equivalent
when using a proper RNG, but the API does not match FIPS 203's internal/external
function separation.

---

### GAP-8: Naming Convention [MINOR]

**FIPS 203 Reference:** Throughout  
**Severity:** Minor — cosmetic

| Aspect | Implementation | FIPS 203 |
|--------|---------------|----------|
| Algorithm name | "Kyber-512/768/1024" | "ML-KEM-512/768/1024" |
| Namespace | `pqcrystals_kyber*` | N/A (standard is name-agnostic) |
| Parameter name | `KYBER_K` | `k` |

No functional impact.

---

### GAP-9: Secret Key Layout Includes H(pk) [INFORMATIONAL]

**FIPS 203 Reference:** Algorithm 16 (ML-KEM.KeyGen_internal), Step 3  
**Severity:** Informational — compliant

**Current implementation:**
```c
// crypto_kem_keypair (kem.c):
sk = [ dk_pke | ek | H(ek) | z ]
```

**FIPS 203 specifies:**
```
dk <- (dk_PKE || ek || H(ek) || z)
```

This matches. The stored `H(ek)` (called `h` in FIPS 203) is pre-computed during
key generation and used in both Encaps and Decaps to avoid recomputing it.

**Status:** COMPLIANT — no gap.

---

## Summary Table

| ID | Gap Description | Severity | FIPS 203 Ref | Files Affected |
|----|----------------|----------|--------------|----------------|
| GAP-1 | Missing `G(d\|\|k)` domain separation | **Critical** | Alg 13 Step 1 | `indcpa.c` |
| GAP-2 | Extra `m <- H(m)` pre-hash in Encaps | **Critical** | Alg 17 Step 1 | `kem.c` |
| GAP-3 | `KDF(K'\|\|H(c))` instead of direct K / `J(z\|\|c)` | **Critical** | Alg 17-18 | `kem.c` |
| GAP-4 | No modulus check on encapsulation key | Moderate | §7.1, Alg 20 | `kem.c`, `poly.c` |
| GAP-5 | No input length/type validation | Moderate | §7.1-7.2 | `kem.c` |
| GAP-6 | 90s primitives not in FIPS 203 | Moderate | §4.1 | `symmetric.h` |
| GAP-7 | d generated internally (not a parameter) | Minor | Alg 13, 16 | `indcpa.c`, `kem.c` |
| GAP-8 | "Kyber" naming instead of "ML-KEM" | Minor | Throughout | All files |
| GAP-9 | Secret key layout | Info | Alg 16 | — (compliant) |

**Critical gaps (1-3)** cause the implementation to produce **different shared secrets**
from identical inputs compared to a FIPS 203 ML-KEM implementation. These are the
algorithmic changes between the 2022 Kyber submission and the 2024 FIPS 203 standard.

**Moderate gap (6)** means that even with algorithmic fixes, full FIPS 203 compliance
requires replacing the 90s symmetric primitives with SHA-3/SHAKE.

---

## Remediation

Partial fixes demonstrating the algorithmic corrections (GAP-1 through GAP-4) are
provided in `components_fips203/`. These retain the 90s symmetric primitives to
maintain compatibility with the existing build system, while implementing the
correct FIPS 203 algorithmic structure.

A KAT test (`sim/validation/kat_test.c`) exercises both the original and FIPS 203
versions with deterministic seeds, confirming they produce **different** outputs
(validating that the fixes actually change behavior) and that each version is
internally self-consistent (encaps/decaps round-trip succeeds).
