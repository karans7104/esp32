#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include "params.h"
#include "kem.h"
#include "indcpa.h"
#include "verify.h"
#include "randombytes.h"

#define NUM_ITERATIONS 50

static double get_time_ms(void) {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart * 1000.0 / (double)freq.QuadPart;
}

/* ============================================================
 *  TEST 1: Correctness — KEM round-trip
 * ============================================================ */
static int test_kem_correctness(void) {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t key_a[CRYPTO_BYTES];
    uint8_t key_b[CRYPTO_BYTES];
    int failures = 0;

    printf("  [TEST 1] KEM Round-Trip Correctness (%d iterations)\n", NUM_ITERATIONS);

    for (int i = 0; i < NUM_ITERATIONS; i++) {
        crypto_kem_keypair(pk, sk);
        crypto_kem_enc(ct, key_b, pk);
        crypto_kem_dec(key_a, ct, sk);

        if (memcmp(key_a, key_b, CRYPTO_BYTES) != 0) {
            printf("    FAIL at iteration %d\n", i + 1);
            failures++;
        }
    }

    printf("    Result: %s (%d/%d passed)\n\n",
           failures == 0 ? "PASSED" : "FAILED",
           NUM_ITERATIONS - failures, NUM_ITERATIONS);
    return failures;
}

/* ============================================================
 *  TEST 2: Ciphertext Tamper Detection
 *  Flipping bits in ciphertext should produce different key
 * ============================================================ */
static int test_ciphertext_tamper(void) {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t ct_tampered[CRYPTO_CIPHERTEXTBYTES];
    uint8_t key_enc[CRYPTO_BYTES];
    uint8_t key_dec[CRYPTO_BYTES];
    uint8_t key_tampered[CRYPTO_BYTES];
    int detected = 0;
    int total = NUM_ITERATIONS;

    printf("  [TEST 2] Ciphertext Tamper Detection (%d iterations)\n", total);

    for (int i = 0; i < total; i++) {
        crypto_kem_keypair(pk, sk);
        crypto_kem_enc(ct, key_enc, pk);

        /* Tamper: flip one random bit in ciphertext */
        memcpy(ct_tampered, ct, CRYPTO_CIPHERTEXTBYTES);
        int byte_pos = i % CRYPTO_CIPHERTEXTBYTES;
        ct_tampered[byte_pos] ^= (1 << (i % 8));

        crypto_kem_dec(key_dec, ct, sk);         /* normal */
        crypto_kem_dec(key_tampered, ct_tampered, sk); /* tampered */

        /* Tampered key must differ from original */
        if (memcmp(key_dec, key_tampered, CRYPTO_BYTES) != 0) {
            detected++;
        }
    }

    printf("    Tamper detected: %d/%d\n", detected, total);
    printf("    Result: %s\n\n",
           detected == total ? "PASSED (all tampering detected)" : "WARNING (some undetected)");
    return detected < total ? 1 : 0;
}

/* ============================================================
 *  TEST 3: Key Independence
 *  Different keypairs must produce different shared secrets
 * ============================================================ */
static int test_key_independence(void) {
    uint8_t pk1[CRYPTO_PUBLICKEYBYTES], sk1[CRYPTO_SECRETKEYBYTES];
    uint8_t pk2[CRYPTO_PUBLICKEYBYTES], sk2[CRYPTO_SECRETKEYBYTES];
    uint8_t ct1[CRYPTO_CIPHERTEXTBYTES], ct2[CRYPTO_CIPHERTEXTBYTES];
    uint8_t key1[CRYPTO_BYTES], key2[CRYPTO_BYTES];
    int independent = 0;
    int total = NUM_ITERATIONS;

    printf("  [TEST 3] Key Independence (%d iterations)\n", total);

    for (int i = 0; i < total; i++) {
        crypto_kem_keypair(pk1, sk1);
        crypto_kem_keypair(pk2, sk2);

        crypto_kem_enc(ct1, key1, pk1);
        crypto_kem_enc(ct2, key2, pk2);

        if (memcmp(key1, key2, CRYPTO_BYTES) != 0) {
            independent++;
        }
    }

    printf("    Independent keys: %d/%d\n", independent, total);
    printf("    Result: %s\n\n",
           independent == total ? "PASSED" : "CONCERN (key collision detected)");
    return independent < total ? 1 : 0;
}

/* ============================================================
 *  TEST 4: Decapsulation with Wrong Secret Key
 *  Using wrong SK must not produce matching key
 * ============================================================ */
static int test_wrong_sk(void) {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    uint8_t pk2[CRYPTO_PUBLICKEYBYTES], sk2[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t key_enc[CRYPTO_BYTES];
    uint8_t key_wrong[CRYPTO_BYTES];
    int rejected = 0;
    int total = NUM_ITERATIONS;

    printf("  [TEST 4] Wrong Secret Key Rejection (%d iterations)\n", total);

    for (int i = 0; i < total; i++) {
        crypto_kem_keypair(pk, sk);
        crypto_kem_keypair(pk2, sk2);  /* different keypair */

        crypto_kem_enc(ct, key_enc, pk);
        crypto_kem_dec(key_wrong, ct, sk2);  /* decrypt with wrong sk */

        if (memcmp(key_enc, key_wrong, CRYPTO_BYTES) != 0) {
            rejected++;
        }
    }

    printf("    Rejected wrong key: %d/%d\n", rejected, total);
    printf("    Result: %s\n\n",
           rejected == total ? "PASSED" : "CRITICAL FAILURE");
    return rejected < total ? 1 : 0;
}

/* ============================================================
 *  TEST 5: Performance Benchmark
 * ============================================================ */
static void test_performance(void) {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t key_a[CRYPTO_BYTES], key_b[CRYPTO_BYTES];

    double keygen_times[NUM_ITERATIONS];
    double enc_times[NUM_ITERATIONS];
    double dec_times[NUM_ITERATIONS];

    printf("  [TEST 5] Performance Benchmark (%d iterations)\n", NUM_ITERATIONS);

    /* warmup */
    crypto_kem_keypair(pk, sk);
    crypto_kem_enc(ct, key_b, pk);
    crypto_kem_dec(key_a, ct, sk);

    for (int i = 0; i < NUM_ITERATIONS; i++) {
        double t0 = get_time_ms();
        crypto_kem_keypair(pk, sk);
        double t1 = get_time_ms();
        crypto_kem_enc(ct, key_b, pk);
        double t2 = get_time_ms();
        crypto_kem_dec(key_a, ct, sk);
        double t3 = get_time_ms();

        keygen_times[i] = t1 - t0;
        enc_times[i]    = t2 - t1;
        dec_times[i]    = t3 - t2;
    }

    double kg_sum = 0, enc_sum = 0, dec_sum = 0;
    double kg_min = keygen_times[0], kg_max = keygen_times[0];
    double enc_min = enc_times[0], enc_max = enc_times[0];
    double dec_min = dec_times[0], dec_max = dec_times[0];

    for (int i = 0; i < NUM_ITERATIONS; i++) {
        kg_sum  += keygen_times[i];
        enc_sum += enc_times[i];
        dec_sum += dec_times[i];
        if (keygen_times[i] < kg_min) kg_min = keygen_times[i];
        if (keygen_times[i] > kg_max) kg_max = keygen_times[i];
        if (enc_times[i] < enc_min) enc_min = enc_times[i];
        if (enc_times[i] > enc_max) enc_max = enc_times[i];
        if (dec_times[i] < dec_min) dec_min = dec_times[i];
        if (dec_times[i] > dec_max) dec_max = dec_times[i];
    }

    printf("    %-20s %10s %10s %10s\n", "Operation", "Avg(ms)", "Min(ms)", "Max(ms)");
    printf("    %-20s %10.4f %10.4f %10.4f\n", "Key Generation", kg_sum / NUM_ITERATIONS, kg_min, kg_max);
    printf("    %-20s %10.4f %10.4f %10.4f\n", "Encapsulation", enc_sum / NUM_ITERATIONS, enc_min, enc_max);
    printf("    %-20s %10.4f %10.4f %10.4f\n", "Decapsulation", dec_sum / NUM_ITERATIONS, dec_min, dec_max);
    printf("\n");

    /* Write CSV */
    FILE *csv = fopen("benchmark_results.csv", "w");
    if (csv) {
        fprintf(csv, "iteration,keygen_ms,encapsulation_ms,decapsulation_ms\n");
        for (int i = 0; i < NUM_ITERATIONS; i++) {
            fprintf(csv, "%d,%.6f,%.6f,%.6f\n", i + 1, keygen_times[i], enc_times[i], dec_times[i]);
        }
        fclose(csv);
        printf("    Benchmark data exported to: benchmark_results.csv\n\n");
    }
}

/* ============================================================
 *  TEST 6: Key Size Verification
 * ============================================================ */
static int test_key_sizes(void) {
    int fail = 0;
    printf("  [TEST 6] Key Size Verification (NIST spec compliance)\n");

#if KYBER_K == 2
    int exp_pk = 800, exp_sk = 1632, exp_ct = 768;
    const char *level = "Kyber-512";
#elif KYBER_K == 3
    int exp_pk = 1184, exp_sk = 2400, exp_ct = 1088;
    const char *level = "Kyber-768";
#elif KYBER_K == 4
    int exp_pk = 1568, exp_sk = 3168, exp_ct = 1568;
    const char *level = "Kyber-1024";
#endif

    printf("    Security level: %s (KYBER_K=%d)\n", level, KYBER_K);
    printf("    Public key:  %4d bytes (expected %d) %s\n", CRYPTO_PUBLICKEYBYTES, exp_pk,
           CRYPTO_PUBLICKEYBYTES == exp_pk ? "OK" : "MISMATCH");
    printf("    Secret key:  %4d bytes (expected %d) %s\n", CRYPTO_SECRETKEYBYTES, exp_sk,
           CRYPTO_SECRETKEYBYTES == exp_sk ? "OK" : "MISMATCH");
    printf("    Ciphertext:  %4d bytes (expected %d) %s\n", CRYPTO_CIPHERTEXTBYTES, exp_ct,
           CRYPTO_CIPHERTEXTBYTES == exp_ct ? "OK" : "MISMATCH");
    printf("    Shared key:  %4d bytes (expected 32) %s\n", CRYPTO_BYTES,
           CRYPTO_BYTES == 32 ? "OK" : "MISMATCH");

    if (CRYPTO_PUBLICKEYBYTES != exp_pk || CRYPTO_SECRETKEYBYTES != exp_sk ||
        CRYPTO_CIPHERTEXTBYTES != exp_ct || CRYPTO_BYTES != 32) {
        fail = 1;
    }

    printf("    Result: %s\n\n", fail == 0 ? "PASSED" : "FAILED");
    return fail;
}

int main(void) {
    int total_failures = 0;

    printf("=============================================================\n");
    printf("  CRYSTALS-KYBER Security & Correctness Analysis\n");
    printf("  Variant: %s | KYBER_K=%d\n", CRYPTO_ALGNAME, KYBER_K);
    printf("=============================================================\n\n");

    total_failures += test_kem_correctness();
    total_failures += test_ciphertext_tamper();
    total_failures += test_key_independence();
    total_failures += test_wrong_sk();
    test_performance();
    total_failures += test_key_sizes();

    printf("=============================================================\n");
    if (total_failures == 0)
        printf("  ALL TESTS PASSED\n");
    else
        printf("  %d TEST(S) FAILED\n", total_failures);
    printf("=============================================================\n");

    return total_failures;
}
