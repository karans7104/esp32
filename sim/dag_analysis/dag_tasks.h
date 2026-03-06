/*
 * dag_tasks.h — Task dependency graph definitions for DAG scheduling analysis
 *
 * Original contribution: models the CRYSTALS-KYBER algorithm as a
 * Directed Acyclic Graph (DAG) for Critical Path Method and
 * List Scheduling analysis.
 *
 * Dependency structure derived from the algorithm flow in:
 *   Segatz & Al Hafiz (2022), Figures 7, 8, 9
 *   and the indcpa.c single-core implementation.
 *
 * Task naming convention:
 *   KG.N  = keypair generation task N
 *   ENC.N = encapsulation task N
 *   DEC.N = decapsulation task N
 */

#ifndef DAG_TASKS_H
#define DAG_TASKS_H

#define MAX_DEPS 4

typedef struct {
    int id;
    const char *name;
    const char *operation;      /* "keypair", "encaps", "decaps" */
    int depends_on[MAX_DEPS];   /* IDs of predecessor tasks (-1 = none) */
    int num_deps;
    double measured_time_us;    /* Filled by task_profiler results */
} DAGTask;

/*
 * ================================================================
 *  KEYPAIR GENERATION DAG
 *
 *  Flow (from indcpa_keypair single-core):
 *    KG.1 → KG.2 ──────────────────────────┐
 *    KG.1 → KG.3 → KG.5 ─┐                 │
 *    KG.1 → KG.4 → KG.6 ─┤                 │
 *                          └→ KG.7 (needs A,ŝ) → KG.8 → KG.9
 *
 *  Segatz dual-core schedule (Figure 7):
 *    Core 0: KG.1 → KG.2 → (wait) → KG.7 → KG.8 → KG.9(pack_pk)
 *    Core 1: (wait) → KG.3 → KG.4 → KG.5 → KG.6 → KG.9(pack_sk)
 * ================================================================
 */
static const DAGTask keypair_dag[] = {
    { 0, "KG.1_seed_expansion",  "keypair", {-1,-1,-1,-1}, 0, 0.0 },
    { 1, "KG.2_gen_matrix_A",    "keypair", { 0,-1,-1,-1}, 1, 0.0 },
    { 2, "KG.3_noise_s",         "keypair", { 0,-1,-1,-1}, 1, 0.0 },
    { 3, "KG.4_noise_e",         "keypair", { 0,-1,-1,-1}, 1, 0.0 },
    { 4, "KG.5_ntt_s",           "keypair", { 2,-1,-1,-1}, 1, 0.0 },
    { 5, "KG.6_ntt_e",           "keypair", { 3,-1,-1,-1}, 1, 0.0 },
    { 6, "KG.7_matmul_As",       "keypair", { 1, 4,-1,-1}, 2, 0.0 },
    { 7, "KG.8_add_reduce",      "keypair", { 6, 5,-1,-1}, 2, 0.0 },
    { 8, "KG.9_pack",            "keypair", { 7,-1,-1,-1}, 1, 0.0 },
};
#define KEYPAIR_DAG_SIZE 9

/*
 * ================================================================
 *  ENCAPSULATION DAG
 *
 *  Flow (from indcpa_enc single-core):
 *    ENC.1 → ENC.2 ─────────────────────────────┐
 *    ENC.1 → ENC.3 → ENC.6 ─┐                   │
 *    ENC.1 → ENC.4           │                   │
 *    ENC.1 → ENC.5           │                   │
 *              └→ ENC.7 (needs A^T, r̂) ──→ ENC.9 ──→ ENC.10 → ENC.11
 *              └→ ENC.8 (needs t, r̂)  ──→ ENC.9 ──┘
 *
 *  Segatz dual-core schedule (Figure 8):
 *    Core 0: ENC.1 → ENC.2 → (wait r̂) → ENC.7 → ENC.9(invntt_u) →
 *            (wait e1) → ENC.10(add e1) → (wait) → ENC.11
 *    Core 1: ENC.3 → ENC.6 → ENC.4 → ENC.5 → ENC.1(frommsg) →
 *            (wait) → ENC.8 → ENC.9(invntt_v) → ENC.10(add e2+m) → ...
 * ================================================================
 */
static const DAGTask encaps_dag[] = {
    { 0, "ENC.1_unpack_pk",       "encaps", {-1,-1,-1,-1}, 0, 0.0 },
    { 1, "ENC.2_gen_matrix_AT",   "encaps", { 0,-1,-1,-1}, 1, 0.0 },
    { 2, "ENC.3_noise_r",         "encaps", { 0,-1,-1,-1}, 1, 0.0 },
    { 3, "ENC.4_noise_e1",        "encaps", { 0,-1,-1,-1}, 1, 0.0 },
    { 4, "ENC.5_noise_e2",        "encaps", { 0,-1,-1,-1}, 1, 0.0 },
    { 5, "ENC.6_ntt_r",           "encaps", { 2,-1,-1,-1}, 1, 0.0 },
    { 6, "ENC.7_matmul_ATr",      "encaps", { 1, 5,-1,-1}, 2, 0.0 },
    { 7, "ENC.8_inner_tTr",       "encaps", { 0, 5,-1,-1}, 2, 0.0 },
    { 8, "ENC.9_invntt",          "encaps", { 6, 7,-1,-1}, 2, 0.0 },
    { 9, "ENC.10_add_errors",     "encaps", { 8, 3, 4,-1}, 3, 0.0 },
    {10, "ENC.11_compress_pack",  "encaps", { 9,-1,-1,-1}, 1, 0.0 },
};
#define ENCAPS_DAG_SIZE 11

/*
 * ================================================================
 *  DECAPSULATION DAG
 *
 *  Flow (from indcpa_dec single-core):
 *    DEC.1 ──→ DEC.3 ──→ DEC.4 ──→ DEC.5 ──→ DEC.6 ──→ DEC.7
 *    DEC.2 ──→ DEC.4
 *
 *  Note: In the full KEM decapsulation (crypto_kem_dec), after
 *  indcpa_dec the result is re-encrypted and compared. The DAG
 *  here covers only the indcpa_dec core since that's what Segatz
 *  parallelized (Figure 9). The re-encryption is sequential.
 *
 *  Segatz dual-core schedule (Figure 9):
 *    Core 0: DEC.2 → (wait) → DEC.4 → DEC.5 → DEC.6 → DEC.7
 *    Core 1: DEC.1 → DEC.3 → (signal core 0)
 * ================================================================
 */
static const DAGTask decaps_dag[] = {
    { 0, "DEC.1_decompress_ct",   "decaps", {-1,-1,-1,-1}, 0, 0.0 },
    { 1, "DEC.2_unpack_sk",       "decaps", {-1,-1,-1,-1}, 0, 0.0 },
    { 2, "DEC.3_ntt_u",           "decaps", { 0,-1,-1,-1}, 1, 0.0 },
    { 3, "DEC.4_inner_sTu",       "decaps", { 1, 2,-1,-1}, 2, 0.0 },
    { 4, "DEC.5_invntt",          "decaps", { 3,-1,-1,-1}, 1, 0.0 },
    { 5, "DEC.6_sub_reduce",      "decaps", { 4,-1,-1,-1}, 1, 0.0 },
    { 6, "DEC.7_decode_msg",      "decaps", { 5,-1,-1,-1}, 1, 0.0 },
};
#define DECAPS_DAG_SIZE 7

/*
 * ================================================================
 *  Segatz's empirical 2-core assignments (from Figures 7, 8, 9)
 *  0 = Core 0, 1 = Core 1
 * ================================================================
 */
static const int segatz_keypair_assignment[] = {
    0,  /* KG.1: Core 0 (seed gen) */
    0,  /* KG.2: Core 0 (gen_matrix A) */
    1,  /* KG.3: Core 1 (noise s) */
    1,  /* KG.4: Core 1 (noise e) */
    1,  /* KG.5: Core 1 (NTT s) */
    1,  /* KG.6: Core 1 (NTT e) */
    0,  /* KG.7: Core 0 (matmul A*s) */
    0,  /* KG.8: Core 0 (add + reduce) */
    0,  /* KG.9: Core 0 (pack pk) — Core 1 packs sk in parallel */
};

static const int segatz_encaps_assignment[] = {
    0,  /* ENC.1:  Core 0 (unpack pk) */
    0,  /* ENC.2:  Core 0 (gen_matrix A^T) */
    1,  /* ENC.3:  Core 1 (noise r) */
    1,  /* ENC.4:  Core 1 (noise e1) */
    1,  /* ENC.5:  Core 1 (noise e2) */
    1,  /* ENC.6:  Core 1 (NTT r) */
    0,  /* ENC.7:  Core 0 (matmul A^T*r) */
    1,  /* ENC.8:  Core 1 (inner t^T*r) */
    0,  /* ENC.9:  Core 0 (invNTT) — split across cores in practice */
    0,  /* ENC.10: Core 0 (add errors) */
    0,  /* ENC.11: Core 0 (compress/pack) */
};

static const int segatz_decaps_assignment[] = {
    1,  /* DEC.1: Core 1 (decompress ct) */
    0,  /* DEC.2: Core 0 (unpack sk) */
    1,  /* DEC.3: Core 1 (NTT u) */
    0,  /* DEC.4: Core 0 (inner s^T*u) */
    0,  /* DEC.5: Core 0 (invNTT) */
    0,  /* DEC.6: Core 0 (sub + reduce) */
    0,  /* DEC.7: Core 0 (decode msg) */
};

#endif /* DAG_TASKS_H */
