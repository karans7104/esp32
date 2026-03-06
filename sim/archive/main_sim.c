#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include "params.h"
#include "kem.h"

#define NUM_ITERATIONS 100

static double get_time_ms(void) {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart * 1000.0 / (double)freq.QuadPart;
}

int main(void) {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t key_a[CRYPTO_BYTES];
    uint8_t key_b[CRYPTO_BYTES];

    double keygen_times[NUM_ITERATIONS];
    double enc_times[NUM_ITERATIONS];
    double dec_times[NUM_ITERATIONS];
    int failures = 0;

    printf("=============================================================\n");
    printf("  CRYSTALS-KYBER KEM Simulation — %s\n", CRYPTO_ALGNAME);
    printf("  Security Level: KYBER_K = %d\n", KYBER_K);
    printf("  Iterations: %d\n", NUM_ITERATIONS);
    printf("=============================================================\n\n");

    /* Warmup run */
    crypto_kem_keypair(pk, sk);
    crypto_kem_enc(ct, key_b, pk);
    crypto_kem_dec(key_a, ct, sk);

    printf("Running %d iterations...\n\n", NUM_ITERATIONS);

    for (int i = 0; i < NUM_ITERATIONS; i++) {
        double t0, t1, t2, t3;

        t0 = get_time_ms();
        crypto_kem_keypair(pk, sk);
        t1 = get_time_ms();

        crypto_kem_enc(ct, key_b, pk);
        t2 = get_time_ms();

        crypto_kem_dec(key_a, ct, sk);
        t3 = get_time_ms();

        keygen_times[i] = t1 - t0;
        enc_times[i]    = t2 - t1;
        dec_times[i]    = t3 - t2;

        if (memcmp(key_a, key_b, CRYPTO_BYTES) != 0) {
            failures++;
            printf("  [FAIL] Iteration %d: key mismatch!\n", i + 1);
        }
    }

    /* Compute statistics */
    double keygen_sum = 0, enc_sum = 0, dec_sum = 0;
    double keygen_min = keygen_times[0], keygen_max = keygen_times[0];
    double enc_min = enc_times[0], enc_max = enc_times[0];
    double dec_min = dec_times[0], dec_max = dec_times[0];

    for (int i = 0; i < NUM_ITERATIONS; i++) {
        keygen_sum += keygen_times[i];
        enc_sum    += enc_times[i];
        dec_sum    += dec_times[i];

        if (keygen_times[i] < keygen_min) keygen_min = keygen_times[i];
        if (keygen_times[i] > keygen_max) keygen_max = keygen_times[i];
        if (enc_times[i] < enc_min) enc_min = enc_times[i];
        if (enc_times[i] > enc_max) enc_max = enc_times[i];
        if (dec_times[i] < dec_min) dec_min = dec_times[i];
        if (dec_times[i] > dec_max) dec_max = dec_times[i];
    }

    double keygen_avg = keygen_sum / NUM_ITERATIONS;
    double enc_avg    = enc_sum / NUM_ITERATIONS;
    double dec_avg    = dec_sum / NUM_ITERATIONS;

    printf("-------------------------------------------------------------\n");
    printf("  CORRECTNESS VERIFICATION\n");
    printf("-------------------------------------------------------------\n");
    printf("  Key agreement check:  %s\n", failures == 0 ? "PASSED (all iterations)" : "FAILED");
    printf("  Failures:             %d / %d\n", failures, NUM_ITERATIONS);
    printf("\n");

    printf("-------------------------------------------------------------\n");
    printf("  PERFORMANCE RESULTS (milliseconds)\n");
    printf("-------------------------------------------------------------\n");
    printf("  %-20s %10s %10s %10s\n", "Operation", "Avg (ms)", "Min (ms)", "Max (ms)");
    printf("  %-20s %10.4f %10.4f %10.4f\n", "Key Generation", keygen_avg, keygen_min, keygen_max);
    printf("  %-20s %10.4f %10.4f %10.4f\n", "Encapsulation", enc_avg, enc_min, enc_max);
    printf("  %-20s %10.4f %10.4f %10.4f\n", "Decapsulation", dec_avg, dec_min, dec_max);
    printf("\n");

    printf("-------------------------------------------------------------\n");
    printf("  ALGORITHM PARAMETERS\n");
    printf("-------------------------------------------------------------\n");
    printf("  Public key size:      %d bytes\n", CRYPTO_PUBLICKEYBYTES);
    printf("  Secret key size:      %d bytes\n", CRYPTO_SECRETKEYBYTES);
    printf("  Ciphertext size:      %d bytes\n", CRYPTO_CIPHERTEXTBYTES);
    printf("  Shared secret size:   %d bytes\n", CRYPTO_BYTES);
    printf("\n");

    printf("-------------------------------------------------------------\n");
    printf("  SHARED SECRET SAMPLE (first iteration)\n");
    printf("-------------------------------------------------------------\n");
    printf("  key_a: ");
    for (int i = 0; i < 16; i++) printf("%02x", key_a[i]);
    printf("...\n");
    printf("  key_b: ");
    for (int i = 0; i < 16; i++) printf("%02x", key_b[i]);
    printf("...\n");
    printf("  Match: %s\n", memcmp(key_a, key_b, CRYPTO_BYTES) == 0 ? "YES" : "NO");
    printf("\n");

    /* Write CSV */
    FILE *csv = fopen("sim_results.csv", "w");
    if (csv) {
        fprintf(csv, "iteration,keygen_ms,enc_ms,dec_ms\n");
        for (int i = 0; i < NUM_ITERATIONS; i++) {
            fprintf(csv, "%d,%.6f,%.6f,%.6f\n", i + 1, keygen_times[i], enc_times[i], dec_times[i]);
        }
        fclose(csv);
        printf("  Results exported to: sim_results.csv\n");
    }

    printf("=============================================================\n");
    printf("  SIMULATION COMPLETE\n");
    printf("=============================================================\n");

    return failures > 0 ? 1 : 0;
}
