# Kybesp32 — CRYSTALS-KYBER on ESP32

An implementation of the [CRYSTALS-KYBER](https://www.pq-crystals.org/kyber/) Key Encapsulation Mechanism (KEM) for the ESP32 platform, built on the [official reference implementation](https://github.com/pq-crystals/kyber). It supports dual-core parallelization and hardware-accelerated SHA/AES via the ESP32's built-in peripherals.

## Features

- **Kyber-512 / Kyber-768 / Kyber-1024** support (configurable via `KYBER_K`)
- **90s variant** using AES-256-CTR + SHA-256/512 (toggle with `KYBER_90S`)
- **Dual-core parallelization** for IND-CPA key generation, encryption, and decryption using FreeRTOS tasks
- **Hardware acceleration** for SHA-256/512 and AES-256 via ESP32's mbedtls backend
- Random number generation using ESP32's hardware RNG (`esp_fill_random`)

## Prerequisites

- [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/) v5.0 or later
- An ESP32 development board (tested on [ESP32-S3-DevKitC-1](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/hw-reference/esp32s3/user-guide-devkitc-1.html))

## Build Instructions

1. Set up the ESP-IDF environment following the [official guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/) or use the [VS Code ESP-IDF extension](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/get-started/vscode-setup.html).

2. Configure the build options in `CMakeLists.txt`:
   ```cmake
   add_compile_definitions("KYBER_90S")           # Use 90s variant
   add_compile_definitions("KYBER_K=2")            # 2=Kyber512, 3=Kyber768, 4=Kyber1024
   add_compile_definitions("SHA_ACC=1")            # 1=Use HW SHA accelerator, 0=Software
   add_compile_definitions("AES_ACC=1")            # 1=Use HW AES accelerator, 0=Software
   add_compile_definitions("INDCPA_KEYPAIR_DUAL=1")# 1=Dual-core keygen, 0=Single-core
   add_compile_definitions("INDCPA_ENC_DUAL=1")    # 1=Dual-core encryption, 0=Single-core
   add_compile_definitions("INDCPA_DEC_DUAL=0")    # 1=Dual-core decryption, 0=Single-core
   ```

3. Build, flash, and monitor:
   ```bash
   idf.py build
   idf.py -p <PORT> flash monitor
   ```

After flashing, the firmware runs a KEM round-trip (keygen → encapsulation → decapsulation) and reports cycle counts over the serial interface.

## Project Structure

```
├── components/
│   ├── aes256ctr/      AES-256 in CTR mode
│   ├── cbd/            Centered Binomial Distribution sampling
│   ├── common/         Shared parameters and config (params.h)
│   ├── fips202/        SHAKE-128/256, SHA3-256/512 (Keccak)
│   ├── indcpa/         IND-CPA public-key encryption (+ dual-core variants)
│   ├── kem/            Key Encapsulation Mechanism (keygen, enc, dec)
│   ├── kex/            Key Exchange protocols (UAKE, AKE)
│   ├── ntt/            Number Theoretic Transform
│   ├── poly/           Polynomial operations
│   ├── polyvec/        Polynomial vector operations
│   ├── randombytes/    RNG wrapper using esp_fill_random
│   ├── reduce/         Montgomery and Barrett reduction
│   ├── sha2/           SHA-256 and SHA-512
│   ├── symmetric/      Symmetric primitive abstractions (AES/SHAKE)
│   └── verify/         Constant-time comparison and conditional move
├── main/
│   ├── main.c          Entry point (app_main) — runs KEM benchmark
│   └── CMakeLists.txt
├── CMakeLists.txt      Top-level build config with compile definitions
└── README.md
```

## Configuration Options

| Define | Values | Description |
|--------|--------|-------------|
| `KYBER_K` | `2`, `3`, `4` | Security level: Kyber-512, 768, or 1024 |
| `KYBER_90S` | defined/undefined | Use AES+SHA (90s) variant vs SHAKE variant |
| `SHA_ACC` | `0`, `1` | Enable ESP32 hardware SHA accelerator |
| `AES_ACC` | `0`, `1` | Enable ESP32 hardware AES accelerator |
| `INDCPA_KEYPAIR_DUAL` | `0`, `1` | Dual-core key pair generation |
| `INDCPA_ENC_DUAL` | `0`, `1` | Dual-core encryption |
| `INDCPA_DEC_DUAL` | `0`, `1` | Dual-core decryption |

## Benchmark Results

Tested on an [ESP32-S3-DevKitC-1](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/hw-reference/esp32s3/user-guide-devkitc-1.html) at 160 MHz, ESP-IDF v5.0, GCC 8.4.0, no compiler optimization. Results for **Kyber-512 (90s variant)**:

### Scenario 1 — Single-core (all optimizations off)

```cmake
SHA_ACC=0, AES_ACC=0, INDCPA_KEYPAIR_DUAL=0, INDCPA_ENC_DUAL=0, INDCPA_DEC_DUAL=0
```

| Algorithm | Cycle Count |
|-----------|------------|
| Key Generation | 2,439,083 |
| Encapsulation | 2,736,256 |
| Decapsulation | 2,736,256 |

### Scenario 2 — Dual-core

```cmake
SHA_ACC=0, AES_ACC=0, INDCPA_KEYPAIR_DUAL=1, INDCPA_ENC_DUAL=1, INDCPA_DEC_DUAL=0
```

| Algorithm | Cycle Count | Speedup |
|-----------|------------|---------|
| Key Generation | 2,007,689 | 1.21x |
| Encapsulation | 2,243,652 | 1.22x |
| Decapsulation | 2,471,286 | 1.20x |

### Scenario 3 — Dual-core + Hardware Accelerators

```cmake
SHA_ACC=1, AES_ACC=1, INDCPA_KEYPAIR_DUAL=1, INDCPA_ENC_DUAL=1, INDCPA_DEC_DUAL=0
```

| Algorithm | Cycle Count | Speedup |
|-----------|------------|---------|
| Key Generation | 1,414,389 | 1.72x |
| Encapsulation | 1,490,784 | 1.84x |
| Decapsulation | 1,756,638 | 1.69x |

### Key Findings

- **Dual-core parallelization** yields ~20% speedup by splitting NTT/noise generation and matrix operations across two cores
- **Hardware SHA + AES acceleration** provides an additional ~40-50% speedup on top of dual-core
- Combined optimizations achieve up to **1.84x** improvement over the single-core baseline
- Decapsulation benefits least from dual-core since `INDCPA_DEC_DUAL` is disabled (it actually slows things down due to synchronization overhead)

## Credits

Based on the [CRYSTALS-KYBER reference implementation](https://github.com/pq-crystals/kyber) by the pq-crystals team.

