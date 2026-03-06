# Software Analysis of CRYSTALS-Kyber ESP32 Implementation: FIPS 203 Compliance Gaps and Optimal Dual-Core Scheduling

**Karan [Last Name]**
[College Name], Department of [Department]
March 2026

---

## Abstract

The transition to post-quantum cryptography demands efficient implementations on resource-constrained embedded platforms. Segatz and Al Hafiz (2022) presented a dual-core implementation of the CRYSTALS-Kyber key encapsulation mechanism on the ESP32 microcontroller, achieving significant speedups through task-level parallelism across two Xtensa LX6 cores. Their work demonstrated that careful partitioning of cryptographic sub-operations between cores could reduce latency for key generation, encapsulation, and decapsulation. However, two questions remained unaddressed: whether their empirical task-to-core assignment constitutes an optimal schedule in the formal scheduling-theoretic sense, and whether the implementation complies with the finalized FIPS 203 standard published by NIST in August 2024. This paper presents a software-based analysis addressing both gaps. The first contribution is a directed acyclic graph (DAG) scheduling analysis that models the three KEM operations as precedence-constrained task graphs and compares the Segatz schedule against the theoretical optimum computed via the Highest Level First with Estimated Times (HLFET) list scheduling algorithm. Under software-only timing weights, the Segatz schedule achieves optimal makespan with a 0.0% gap across all three operations. However, a sensitivity analysis simulating ESP32 hardware SHA and AES accelerators reveals that the gap opens to 6.7% for encapsulation when cryptographic primitives are accelerated by factors of 6.1x (SHA) and 9.65x (AES), as reported by Segatz. The second contribution is a FIPS 203 compliance gap analysis that identifies nine gaps between the implementation and the finalized standard, including three critical algorithmic differences that cause the implementation to produce different shared secrets from a conforming ML-KEM implementation. Partial algorithmic fixes are provided and validated through divergence testing across all three parameter sets.

---

## 1. Introduction

The impending threat of large-scale quantum computers to classical public-key cryptography has motivated a global effort to standardize post-quantum cryptographic algorithms. Shor's algorithm, when executed on a sufficiently powerful quantum computer, can efficiently solve the integer factorization and discrete logarithm problems that underpin RSA and elliptic curve cryptography. In response, the National Institute of Standards and Technology (NIST) initiated a multi-year standardization process in 2016, evaluating candidate algorithms for key encapsulation and digital signatures. In July 2022, NIST announced that CRYSTALS-Kyber had been selected as the primary key encapsulation mechanism (KEM) for standardization, citing its strong security margins, compact key and ciphertext sizes, and computational efficiency across platforms (NIST, 2022).

The Internet of Things (IoT) represents a domain where the transition to post-quantum cryptography is both urgent and challenging. IoT devices such as sensor nodes, industrial controllers, and smart home equipment typically operate under severe constraints in processing power, memory, and energy. Yet these devices frequently handle sensitive data and must establish secure communication channels, often with cloud servers that will be among the first systems to adopt post-quantum standards. The ESP32 microcontroller, manufactured by Espressif Systems, is one of the most widely deployed IoT platforms worldwide. Its dual-core Xtensa LX6 architecture running at 240 MHz, combined with hardware accelerators for SHA and AES operations, makes it a compelling target for post-quantum cryptographic implementations.

Segatz and Al Hafiz (2022) addressed this challenge by implementing CRYSTALS-Kyber on the ESP32, exploiting the dual-core architecture to parallelize key generation, encapsulation, and decapsulation. Their implementation used the 90s variant of Kyber, which relies on AES-256-CTR and SHA-2 instead of SHAKE and SHA-3, enabling the use of the ESP32's hardware accelerators. They reported speedups through task-level parallelism, with core-to-task assignments derived through an empirical approach, as the authors described.

Two significant questions remained open after their work. First, while their dual-core schedule was empirically effective, it was not formally analyzed against scheduling-theoretic optimality bounds. Given that the three KEM operations decompose naturally into precedence-constrained task graphs, established results from DAG scheduling theory can provide rigorous optimality guarantees or identify improvement opportunities. Second, the CRYSTALS-Kyber specification underwent substantial changes between its 2022 selection and its August 2024 publication as FIPS 203 (NIST, 2024). Several algorithmic modifications were introduced in the final standard, and the 90s variant was not included in the standardized specification at all.

This paper presents two contributions that address these gaps. The first is a formal DAG scheduling analysis comparing the Segatz dual-core assignment against the optimal two-processor schedule computed by the HLFET list scheduling algorithm. The second is a systematic FIPS 203 compliance gap analysis identifying all deviations between the implementation and the finalized standard, with partial fixes and validation tests.

---

## 2. Background

### 2.1 CRYSTALS-Kyber and ML-KEM

CRYSTALS-Kyber is a lattice-based key encapsulation mechanism whose security rests on the hardness of the Module Learning With Errors (MLWE) problem (Avanzi et al., 2021). The algorithm operates over the polynomial ring $R_q = \mathbb{Z}_q[X]/(X^{256}+1)$ with modulus $q = 3329$ and degree $n = 256$. It consists of three operations: key generation produces a public encapsulation key and a private decapsulation key; encapsulation takes the public key and produces a shared secret along with a ciphertext; and decapsulation recovers the shared secret from the ciphertext using the private key.

Internally, Kyber is constructed as an IND-CCA2 secure KEM by applying the Fujisaki-Okamoto (FO) transform to an underlying IND-CPA secure public-key encryption scheme called K-PKE. The FO transform adds re-encryption verification during decapsulation: the decrypted message is re-encrypted, and if the resulting ciphertext does not match the received one, an implicit rejection value is returned instead of the genuine shared secret. This mechanism provides security against adaptive chosen-ciphertext attacks.

Kyber defines three parameter sets corresponding to different security levels: Kyber-512 ($k=2$, NIST security level 1), Kyber-768 ($k=3$, level 3), and Kyber-1024 ($k=4$, level 5). The parameter $k$ determines the dimension of the module lattice and directly affects key sizes, ciphertext sizes, and computational cost. All three parameter sets share the same modulus $q = 3329$ and degree $n = 256$, with identical core arithmetic operations differing only in the number of polynomial multiplications required.

Following standardization, the algorithm was published as FIPS 203 under the name ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism). The finalized standard introduced several algorithmic changes from the 2022 Kyber submission, which are detailed in Section 2.4.

### 2.2 ESP32 Platform

The ESP32 is a system-on-chip (SoC) featuring two Xtensa LX6 cores operating at up to 240 MHz, 520 KB of SRAM, and integrated Wi-Fi and Bluetooth connectivity. For cryptographic workloads, the chip includes hardware accelerators for SHA (supporting SHA-1, SHA-256, SHA-384, and SHA-512) and AES (supporting 128, 192, and 256-bit key lengths in various modes including CTR). These accelerators operate independently of the CPU cores, enabling concurrent computation.

Segatz and Al Hafiz (2022) exploited this architecture by decomposing each KEM operation into sub-tasks and assigning them across the two cores using FreeRTOS semaphores for synchronization. Their reported results showed that the SHA hardware accelerator provided a speedup factor of approximately 6.1x over software implementation, and the AES accelerator achieved approximately 9.65x speedup. These acceleration factors are central to the sensitivity analysis presented in Section 5.3 of this paper.

### 2.3 DAG Scheduling Theory

In parallel computing, a program's computational structure can be modeled as a directed acyclic graph (DAG) $G = (V, E)$, where each vertex $v \in V$ represents a task with an associated execution time (weight), and each directed edge $(u, v) \in E$ represents a precedence constraint requiring task $u$ to complete before task $v$ can begin. The scheduling problem asks: given $P$ identical processors and a task DAG, find an assignment of tasks to processors and a start time for each task that minimizes the overall completion time (makespan) while respecting all precedence constraints.

The Critical Path Method (CPM) computes the longest weighted path from any source to any sink in the DAG. The critical path length provides a fundamental lower bound on the makespan: no schedule, regardless of the number of processors, can achieve a completion time shorter than the critical path. A second lower bound is $W/P$, where $W$ is the total work (sum of all task weights) and $P$ is the number of processors.

The HLFET list scheduling algorithm is a well-established heuristic for multiprocessor scheduling. It assigns priorities to tasks based on their static level, defined as the length of the longest path from the task to any exit node. At each scheduling step, the ready task with the highest priority is assigned to the processor that allows the earliest start time. For the special case of two processors with unit-weight tasks on a tree-structured DAG, list scheduling is known to produce optimal schedules. While optimality is not guaranteed for arbitrary DAGs with non-unit weights, the HLFET algorithm provides a strong practical bound and is widely used as a reference scheduler in the parallel computing literature.

### 2.4 FIPS 203 Standardization

Between the July 2022 selection of Kyber and the August 2024 publication of FIPS 203, NIST introduced several modifications to the algorithm. The most significant changes affect the KEM layer rather than the underlying K-PKE encryption scheme's core arithmetic. First, the key generation function now includes a domain separation byte: the hash function G is applied to $d \| k$ (33 bytes) rather than $d$ alone (32 bytes), where $k$ is the parameter set identifier. This prevents identical seeds from producing identical keys across different security levels.

Second, the encapsulation function no longer applies a pre-hash to the random message $m$. The original Kyber specification included a step $m \leftarrow H(m)$ as a defense against poor random number generators, but FIPS 203 removed this step, trusting the RNG to produce high-quality randomness (NIST, 2024, Section 3.3).

Third, the shared secret derivation was simplified. The original Kyber computed $K = \text{KDF}(K' \| H(c))$, incorporating a hash of the ciphertext into the final shared secret. FIPS 203 instead uses $K$ directly from the output of $G(m \| H(ek))$, without additional hashing. Similarly, the implicit rejection mechanism changed from using $z$ with a hash of the ciphertext to computing $J(z \| c)$ where $J$ is SHAKE-256 applied to the concatenation of the rejection seed and the full ciphertext.

Fourth, FIPS 203 mandated a modulus check on the encapsulation key: before encapsulation, every decoded coefficient must be verified to lie in the range $[0, q-1]$.

Finally, and critically for the implementation under study, FIPS 203 standardized only the SHA-3/SHAKE-based instantiation of ML-KEM. The 90s variant using AES-256-CTR and SHA-2, which was included in the Kyber submission for performance comparison purposes, was not adopted into the final standard.

---

## 3. Methodology

### 3.1 PC Simulation Framework

To enable analysis without requiring ESP32 hardware, a PC-based simulation framework was developed that compiles the original ESP32 Kyber source code natively on a Windows workstation using GCC (MinGW). The FreeRTOS dual-core primitives (task creation, semaphore synchronization) were bypassed by compiling with all dual-core flags disabled, yielding single-threaded execution of each KEM operation. The ESP32's hardware random number generator was replaced with Windows CryptGenRandom via the platform abstraction layer.

This approach is valid for scheduling analysis because the relative ordering and dependency structure of sub-tasks is preserved regardless of the execution platform. The absolute execution times differ from ESP32 measurements, but the DAG structure and dependency edges are identical to those in the ESP32 firmware. The sensitivity analysis in Section 5.3 addresses the timing discrepancy by applying scaling factors derived from Segatz's reported hardware accelerator speedups.

### 3.2 Task Profiling

Each KEM operation was decomposed into the sub-tasks identified in Segatz and Al Hafiz (2022): nine tasks for key generation, eleven for encapsulation, and seven for decapsulation, totaling 27 distinct sub-tasks. Each sub-task was individually timed using the Windows QueryPerformanceCounter API over 1000 iterations, with average, minimum, and maximum execution times recorded. The profiling was performed for all three parameter sets (Kyber-512 with $k=2$, Kyber-768 with $k=3$, and Kyber-1024 with $k=4$), producing per-task timing data in both CSV and JSON formats.

### 3.3 DAG Construction

The task dependency graphs were constructed by mapping the computational flow diagrams presented in Figures 7, 8, and 9 of Segatz and Al Hafiz (2022) to formal DAG representations. Each sub-task became a vertex with its measured average execution time as the weight. Directed edges were added to encode data dependencies: for example, in key generation, the matrix-vector multiplication task KG.7 depends on both the matrix generation task KG.2 (which produces matrix $\hat{A}$) and the NTT of the secret vector task KG.5 (which produces $\hat{s}$). The Segatz dual-core assignment was encoded as a separate data structure recording which core each task was assigned to and at what time it began execution, exactly matching the partitioning shown in their paper.

### 3.4 FIPS 203 Audit Methodology

The FIPS 203 compliance audit was conducted by systematically comparing each function in the implementation source code against the corresponding algorithm in the FIPS 203 standard document. The audit covered the parameter definitions (`params.h`), the K-PKE functions (`indcpa.c`), the KEM functions (`kem.c`), the symmetric primitive bindings (`symmetric.h`, `symmetric-aes.c`), the NTT implementation (`ntt.c`), and the verification utilities (`verify.c`). Each deviation was classified by severity (Critical, Moderate, Minor, or Informational) and mapped to a specific FIPS 203 algorithm and step number. Partial fixes addressing the critical and moderate algorithmic gaps were implemented in a separate `components_fips203/` directory, preserving the original code for comparison. A Known Answer Test (KAT) suite was developed to validate both versions and confirm divergence.

---

## 4. Results

### 4.1 Task Profiling Results

Table 1 presents the measured average execution times for all 27 sub-tasks of Kyber-512 on the PC simulation platform, averaged over 1000 iterations per task.

**Table 1: Task Execution Times for Kyber-512 (PC Platform)**

| Task | Operation | Avg (μs) | Min (μs) | Max (μs) |
|------|-----------|----------|----------|----------|
| KG.1 Seed expansion (SHA-512) | KeyGen | 249.58 | 146.20 | 12087.70 |
| KG.2 Generate matrix A (AES-CTR) | KeyGen | 76.03 | 52.20 | 483.90 |
| KG.3 Noise sampling s (AES-CTR) | KeyGen | 18.30 | 12.90 | 78.90 |
| KG.4 Noise sampling e (AES-CTR) | KeyGen | 18.66 | 12.80 | 418.20 |
| KG.5 NTT(s) | KeyGen | 5.66 | 3.90 | 79.20 |
| KG.6 NTT(e) | KeyGen | 5.36 | 3.70 | 170.00 |
| KG.7 Matrix-vector multiply A·s | KeyGen | 8.76 | 6.30 | 49.70 |
| KG.8 Add and reduce | KeyGen | 1.27 | 0.90 | 19.10 |
| KG.9 Pack keys | KeyGen | 1.22 | 0.80 | 21.70 |
| ENC.1 Unpack pk | Encaps | 1.06 | 0.70 | 11.40 |
| ENC.2 Generate matrix A^T (AES-CTR) | Encaps | 74.38 | 50.20 | 527.30 |
| ENC.3 Noise sampling r (AES-CTR) | Encaps | 19.21 | 12.90 | 281.80 |
| ENC.4 Noise sampling e1 (AES-CTR) | Encaps | 15.37 | 10.40 | 216.60 |
| ENC.5 Noise sampling e2 (AES-CTR) | Encaps | 7.80 | 5.20 | 165.50 |
| ENC.6 NTT(r) | Encaps | 5.65 | 3.90 | 42.20 |
| ENC.7 Matrix-vector multiply A^T·r | Encaps | 8.32 | 5.70 | 300.00 |
| ENC.8 Inner product t^T·r | Encaps | 4.11 | 2.80 | 91.10 |
| ENC.9 Inverse NTT | Encaps | 13.14 | 9.30 | 144.70 |
| ENC.10 Add errors | Encaps | 2.02 | 1.40 | 22.30 |
| ENC.11 Compress and pack | Encaps | 2.38 | 1.60 | 65.50 |
| DEC.1 Decompress ciphertext | Decaps | 1.37 | 0.90 | 16.40 |
| DEC.2 Unpack sk | Decaps | 0.56 | 0.30 | 11.70 |
| DEC.3 NTT(u) | Decaps | 5.49 | 3.80 | 96.20 |
| DEC.4 Inner product s^T·u | Decaps | 4.04 | 2.80 | 69.50 |
| DEC.5 Inverse NTT | Decaps | 4.64 | 3.10 | 97.00 |
| DEC.6 Subtract and reduce | Decaps | 0.74 | 0.40 | 30.80 |
| DEC.7 Decode message | Decaps | 1.47 | 0.50 | 695.20 |

The profiling reveals extreme weight imbalance across sub-tasks. In key generation, the seed expansion task KG.1 accounts for 249.58 μs out of a total work of 384.83 μs, representing 64.9% of the entire operation. The matrix generation task KG.2 contributes a further 76.03 μs (19.8%), meaning that two tasks together account for 84.6% of key generation time. Both of these tasks involve cryptographic hash or cipher operations (SHA-512 and AES-256-CTR respectively), which are precisely the operations accelerated by ESP32 hardware.

In encapsulation, the matrix generation task ENC.2 dominates at 74.38 μs out of 153.43 μs total work (48.5%). The noise sampling tasks ENC.3, ENC.4, and ENC.5 collectively contribute 42.38 μs (27.6%). As in key generation, these AES-CTR-based tasks are disproportionately expensive in software but would be dramatically accelerated on ESP32 hardware.

Decapsulation exhibits the least weight imbalance, with a total work of only 18.32 μs. The NTT computation DEC.3 (5.49 μs) and inverse NTT DEC.5 (4.64 μs) are the largest tasks, but no single task dominates to the extent seen in key generation or encapsulation. Notably, decapsulation involves no SHA or AES operations at the sub-task level profiled here, making it insensitive to hardware acceleration.

### 4.2 Critical Path Analysis

The critical path — the longest weighted path through the task dependency DAG — determines the theoretical minimum makespan regardless of the number of available processors. Table 2 summarizes the critical path analysis for each KEM operation.

**Table 2: Critical Path Analysis for Kyber-512**

| Operation | Total Work (μs) | Critical Path (μs) | CP/Work Ratio | Max Speedup |
|-----------|-----------------|---------------------|---------------|-------------|
| KeyGen | 384.83 | 336.86 | 87.5% | 1.14x |
| Encaps | 153.43 | 101.29 | 66.0% | 1.51x |
| Decaps | 18.32 | 17.75 | 96.9% | 1.03x |

The critical path for key generation follows the sequence KG.1 (seed expansion) → KG.2 (matrix A generation) → KG.7 (matrix-vector multiply) → KG.8 (add and reduce) → KG.9 (pack), totaling 336.86 μs. This path consumes 87.5% of the total work, leaving only 12.5% of computation (the noise sampling and NTT tasks on the secret and error vectors) available for parallel execution on a second core. The theoretical maximum speedup is therefore bounded at $384.83 / 336.86 = 1.14$x.

The critical path for encapsulation follows ENC.1 (unpack pk) → ENC.2 (matrix A^T generation) → ENC.7 (matrix-vector multiply) → ENC.9 (inverse NTT) → ENC.10 (add errors) → ENC.11 (compress and pack), totaling 101.29 μs. With a CP/Work ratio of 66.0%, encapsulation offers the most parallelism, with a theoretical maximum speedup of 1.51x.

Decapsulation has the least parallelism, with the critical path consuming 96.9% of total work. The critical path follows DEC.1 (decompress) → DEC.3 (NTT) → DEC.4 (inner product) → DEC.5 (inverse NTT) → DEC.6 (subtract) → DEC.7 (decode), and the only task that can execute in parallel is DEC.2 (unpack sk), which takes just 0.56 μs.

### 4.3 Scheduling Analysis

Table 3 presents the central scheduling comparison under three timing scenarios. Scenario A uses raw PC profiling weights. Scenarios B and C apply scaling factors to SHA- and AES-accelerated tasks, simulating ESP32 hardware.

**Table 3: Scheduling Comparison Across Three Scenarios (Kyber-512)**

| Scenario | Operation | Segatz (μs) | Optimal (μs) | Gap | Speedup |
|----------|-----------|-------------|--------------|-----|---------|
| A: PC baseline | KeyGen | 336.86 | 336.86 | 0.0% | 1.14x |
| A: PC baseline | Encaps | 101.29 | 101.29 | 0.0% | 1.51x |
| A: PC baseline | Decaps | 17.75 | 17.75 | 0.0% | 1.03x |
| B: HW accel (SHA/6.1x, AES/9.65x) | KeyGen | 61.66 | 60.05 | 2.7% | 1.25x |
| B: HW accel (SHA/6.1x, AES/9.65x) | Encaps | 36.96 | 34.62 | 6.7% | 1.41x |
| B: HW accel (SHA/6.1x, AES/9.65x) | Decaps | 17.75 | 17.75 | 0.0% | 1.03x |
| C: Conservative (SHA/4x, AES/6x) | KeyGen | 86.32 | 86.32 | 0.0% | 1.20x |
| C: Conservative (SHA/4x, AES/6x) | Encaps | 39.63 | 39.31 | 0.8% | 1.43x |
| C: Conservative (SHA/4x, AES/6x) | Decaps | 17.75 | 17.75 | 0.0% | 1.03x |

Under Scenario A (PC baseline weights), the Segatz schedule achieves optimal makespan for all three operations with a 0.0% gap. This result is explained by the extreme weight imbalance in the task graphs. The critical path through the heaviest tasks (seed expansion and matrix generation) is so dominant that the off-critical-path tasks — noise sampling and NTT operations — fit comfortably within the slack on the second core regardless of how they are ordered. Any valid schedule that places the critical path on one core and the remaining tasks on the other achieves the same makespan.

Scenario B applies the hardware accelerator speedup factors reported by Segatz and Al Hafiz (2022): 6.1x for SHA operations and 9.65x for AES-CTR operations. Under these accelerated weights, the gap opens. For key generation, the Segatz schedule achieves 61.66 μs versus the optimal 60.05 μs, a gap of 2.7%. For encapsulation, the gap widens to 6.7%, with the Segatz schedule at 36.96 μs versus the optimal 34.62 μs. The mechanism is clear: hardware acceleration disproportionately shrinks the dominant SHA and AES tasks that formerly constituted the critical path, making the remaining arithmetic tasks (NTT, matrix multiplication) relatively more significant. With more balanced task weights, the scheduling assignment matters, and the Segatz assignment is no longer optimal.

Under Scenario C (conservative acceleration of 4x SHA and 6x AES), the encapsulation gap is 0.8%, and key generation remains optimal. This confirms that the scheduling gap is a continuous function of the acceleration ratio: it emerges only when acceleration is strong enough to rebalance task weights.

Decapsulation remains optimally scheduled across all scenarios because it contains no SHA or AES tasks and thus is unaffected by hardware acceleration.

### 4.4 FIPS 203 Gap Analysis

The compliance audit identified nine gaps between the implementation and FIPS 203, summarized in Table 4.

**Table 4: FIPS 203 Compliance Gaps**

| ID | Description | Severity | FIPS 203 Reference |
|----|-------------|----------|--------------------|
| GAP-1 | Missing G(d‖k) domain separation in K-PKE.KeyGen | Critical | Algorithm 13, Step 1 |
| GAP-2 | Extra m ← H(m) pre-hash in ML-KEM.Encaps | Critical | Algorithm 17, Step 1 |
| GAP-3 | KDF(K'‖H(c)) instead of direct K; missing J(z‖c) | Critical | Algorithms 17-18 |
| GAP-4 | No modulus check on encapsulation key | Moderate | §7.1, Algorithm 20 |
| GAP-5 | No input length/type validation | Moderate | §7.1-7.2 |
| GAP-6 | 90s symmetric primitives not standardized | Moderate | §4.1 |
| GAP-7 | Seed d generated internally, not as parameter | Minor | Algorithms 13, 16 |
| GAP-8 | Uses "Kyber" naming instead of "ML-KEM" | Minor | Throughout |
| GAP-9 | Secret key layout dk = dk_pke‖ek‖H(ek)‖z | Informational | Algorithm 16 (compliant) |

The three critical gaps all affect the computation of the shared secret, meaning that this implementation and a conforming FIPS 203 ML-KEM implementation cannot interoperate even if given identical inputs.

GAP-1 concerns the key generation function K-PKE.KeyGen. FIPS 203 Algorithm 13 specifies that the hash function G is applied to the concatenation of the random seed $d$ and the parameter set byte $k$, producing 33 bytes of input. The implementation applies G to $d$ alone (32 bytes), omitting the domain separation byte. This means that the same seed $d$ would produce identical keys regardless of security level, which FIPS 203 explicitly prevents.

GAP-2 concerns encapsulation. The original Kyber specification included a step $m \leftarrow H(m)$ that pre-hashed the random message before use. FIPS 203 Algorithm 17 removed this step, using $m$ directly as sampled. The implementation retains the pre-hash, causing the shared secret to diverge from a compliant implementation even when using the same random input.

GAP-3 is the most structurally significant. The original Kyber derived the shared secret as $K = \text{KDF}(K' \| H(c))$, incorporating a hash of the ciphertext, and used a simple conditional move for implicit rejection. FIPS 203 instead uses $K$ directly from the G output (no additional KDF) and computes the implicit rejection value as $K_{\text{bar}} = J(z \| c)$, where J operates on the full ciphertext rather than its hash. These changes simplify the shared secret derivation while maintaining IND-CCA2 security.

GAP-6 represents a fundamental limitation: FIPS 203 standardized only the SHA-3/SHAKE-based instantiation of ML-KEM. The 90s variant using AES-256-CTR (as XOF and PRF) and SHA-2 (as H and G) was not included in the final standard. Consequently, even with all algorithmic corrections applied, this implementation cannot produce FIPS 203-compliant output because the underlying symmetric primitives differ.

The partial fixes implemented in `components_fips203/` address GAPs 1 through 4 at the algorithmic level while retaining the 90s symmetric primitives. A KAT test suite exercises both the original and corrected implementations with deterministic seeds. The divergence test confirms that the original and FIPS 203 versions produce different public keys in 20 out of 20 trials and different shared secrets in 20 out of 20 trials, validating that the fixes produce materially different outputs. Both versions pass internal round-trip consistency (encapsulation followed by decapsulation yields the same shared secret) across all three parameter sets (Kyber-512, 768, and 1024).

---

## 5. Discussion

The scheduling analysis reveals that the bottleneck in dual-core Kyber is algorithmic, not scheduling-related. Under software-only timing, the critical path through seed expansion and matrix generation is so dominant that it leaves insufficient parallel work to benefit from scheduling optimization. The Segatz schedule is optimal not because of careful scheduling but because the problem structure makes virtually any valid schedule optimal. This finding connects directly to an observation made by Segatz and Al Hafiz (2022) themselves, who identified matrix A generation as a candidate for future optimization due to its outsized contribution to latency.

The sensitivity analysis provides a more nuanced picture. When hardware accelerators compress the SHA and AES tasks that dominate the critical path, the remaining polynomial arithmetic tasks become relatively more expensive, and the optimal schedule must account for their placement. The 6.7% gap in encapsulation under Scenario B hardware acceleration represents a concrete scheduling improvement opportunity: the HLFET list scheduler finds a task assignment that completes 2.34 μs earlier than the Segatz assignment by more efficiently interleaving noise sampling and NTT tasks with the matrix multiplication steps.

From a practical standpoint, the 6.7% gap translates to a modest absolute time saving. However, in high-throughput IoT scenarios where a device performs thousands of encapsulations (for example, a gateway establishing sessions with multiple clients), cumulative savings become meaningful. More importantly, the result demonstrates that scheduling analysis should be revisited whenever the underlying execution weights change, whether due to hardware acceleration, algorithmic optimization, or platform migration.

The FIPS 203 findings have more immediate practical implications. Any device running the current implementation cannot establish shared secrets with a server implementing standardized ML-KEM. The three critical gaps cause output divergence at every stage: key generation produces different public keys (GAP-1), encapsulation produces different shared secrets (GAP-2 and GAP-3), and decapsulation uses a different implicit rejection mechanism (GAP-3). For IoT devices being deployed today that must interoperate with modern TLS 1.3 stacks incorporating ML-KEM, this incompatibility is a deployment blocker.

The combined implication of both analyses is that the implementation requires two categories of updates for continued relevance. First, the task-to-core assignment should be revisited with hardware-accurate timing weights, particularly for encapsulation. Second, and more urgently, the KEM-layer algorithms must be updated to match FIPS 203, and the 90s symmetric primitives should be migrated to SHA-3/SHAKE for full compliance. These two updates are largely independent: the scheduling optimization operates at the sub-task level within K-PKE, while the FIPS 203 compliance fixes operate at the KEM wrapper level.

---

## 6. Limitations

Several limitations of this work should be acknowledged explicitly. The task execution times were measured on a PC platform (Windows, x86-64 architecture) rather than on ESP32 hardware. While the DAG structure and dependency relationships are identical across platforms, the absolute and relative task weights differ. The PC's out-of-order superscalar pipeline handles AES and SHA computations differently than the ESP32's in-order Xtensa cores with dedicated accelerators, meaning the baseline weight ratios do not reflect actual ESP32 execution ratios.

The sensitivity analysis addresses this limitation by applying scalar multipliers derived from the hardware accelerator speedup factors reported by Segatz and Al Hafiz (2022). However, these multipliers are applied uniformly to entire task categories (all SHA tasks scaled by 6.1x, all AES tasks scaled by 9.65x). In practice, the actual speedup may vary by task due to differences in input size, memory access patterns, and accelerator pipeline effects. The sensitivity analysis therefore represents an analytical model of hardware acceleration, not a direct measurement.

The FIPS 203 fixes implemented in `components_fips203/` retain the 90s symmetric primitives (SHA-256, SHA-512, AES-256-CTR) rather than migrating to the FIPS 203-mandated SHA-3/SHAKE primitives. This means the fixes demonstrate the correct algorithmic structure but do not produce FIPS 203-compliant output. Full compliance would require replacing the symmetric primitive layer, which is beyond the scope of this analysis.

The KAT test suite validates internal consistency (each version's encaps and decaps agree) and confirms divergence between versions (same seeds produce different outputs). It does not validate against NIST's official ML-KEM Known Answer Test vectors, because no official KAT vectors exist for the 90s variant, which was not standardized. Validation against the official ML-KEM KAT vectors would require completing the SHA-3/SHAKE migration first.

Finally, the optimal schedule identified by the HLFET list scheduler has not been validated on ESP32 hardware. Implementing the revised task assignment would require modifying the FreeRTOS task creation and semaphore synchronization code, rebuilding the firmware, and measuring actual execution times. This hardware validation remains future work.

---

## 7. Conclusion

This paper presented two complementary contributions analyzing the dual-core CRYSTALS-Kyber implementation by Segatz and Al Hafiz (2022) on the ESP32 microcontroller. The first contribution established that their empirical dual-core task assignment is formally optimal under software-only timing weights, achieving a 0.0% gap relative to the HLFET list scheduling lower bound for all three KEM operations: key generation (336.86 μs, 1.14x speedup), encapsulation (101.29 μs, 1.51x speedup), and decapsulation (17.75 μs, 1.03x speedup). However, a sensitivity analysis incorporating ESP32 hardware accelerator speedup factors of 6.1x for SHA and 9.65x for AES revealed that the Segatz schedule becomes suboptimal under hardware acceleration, with the gap reaching 6.7% for encapsulation (36.96 μs Segatz vs. 34.62 μs optimal) and 2.7% for key generation (61.66 μs vs. 60.05 μs).

The second contribution identified nine compliance gaps between the implementation and the finalized FIPS 203 (ML-KEM) standard, including three critical algorithmic differences that cause the implementation to produce shared secrets incompatible with any conforming ML-KEM implementation. Partial fixes addressing the critical gaps were implemented and validated through divergence testing, confirming that the algorithmic changes produce materially different outputs across all three parameter sets.

Future work should pursue three directions. First, the optimal schedule identified by the HLFET analysis should be implemented in the ESP32 firmware and validated with hardware timing measurements to confirm the predicted improvement under actual acceleration conditions. Second, the symmetric primitive layer should be migrated from the 90s variant (SHA-2, AES-256-CTR) to the FIPS 203-mandated primitives (SHA-3, SHAKE-128, SHAKE-256) to achieve full standards compliance. Third, the observation that matrix A generation dominates the critical path across all scenarios suggests that algorithmic optimization of this step, perhaps through lazy or incremental expansion techniques, would yield larger speedup improvements than any scheduling rearrangement.

---

## References

Avanzi, R., Bos, J., Ducas, L., Kiltz, E., Lepoint, T., Lyubashevsky, V., Schanck, J. M., Schwabe, P., Seiler, G., and Stehlé, D. (2021). CRYSTALS-Kyber: Algorithm Specifications and Supporting Documentation (version 3.02). NIST Post-Quantum Cryptography Standardization, Round 3 Submission.

Bos, J., Ducas, L., Kiltz, E., Lepoint, T., Lyubashevsky, V., Schanck, J. M., Schwabe, P., Seiler, G., and Stehlé, D. (2021). pq-crystals/kyber: Reference Implementation. Available at: https://github.com/pq-crystals/kyber

National Institute of Standards and Technology (NIST). (2022). NIST Announces First Four Quantum-Resistant Cryptographic Algorithms. NIST News, July 5, 2022.

National Institute of Standards and Technology (NIST). (2024). FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard. Federal Information Processing Standards Publication 203, August 2024.

Segatz, F. and Al Hafiz, M. I. A. (2022). Efficient Implementation of CRYSTALS-KYBER Key Encapsulation Mechanism on ESP32. arXiv preprint arXiv:2503.10207 [cs.CR].
