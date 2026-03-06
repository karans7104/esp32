@echo off
echo ================================================================
echo   CRYSTALS-KYBER Multi-Level Comparison Analysis
echo   Comparing Kyber-512, Kyber-768, and Kyber-1024
echo ================================================================
echo.

set CC=gcc
set BASE_FLAGS=-O2 -Wall -DKYBER_90S -DSHA_ACC=0 -DAES_ACC=0 -DINDCPA_KEYPAIR_DUAL=0 -DINDCPA_ENC_DUAL=0 -DINDCPA_DEC_DUAL=0
set INCLUDES=-I..\components\common -I..\components\kem -I..\components\indcpa -I..\components\poly -I..\components\polyvec -I..\components\ntt -I..\components\reduce -I..\components\cbd -I..\components\symmetric -I..\components\aes256ctr -I..\components\fips202 -I..\components\sha2 -I..\components\randombytes -I..\components\verify -I..\components\kex
set SRCS=security_analysis.c randombytes_pc.c ..\components\kem\kem.c ..\components\indcpa\indcpa.c ..\components\poly\poly.c ..\components\polyvec\polyvec.c ..\components\ntt\ntt.c ..\components\reduce\reduce.c ..\components\cbd\cbd.c ..\components\symmetric\symmetric-aes.c ..\components\symmetric\symmetric-shake.c ..\components\aes256ctr\aes256ctr.c ..\components\fips202\fips202.c ..\components\sha2\sha256.c ..\components\sha2\sha512.c ..\components\verify\verify.c ..\components\kex\kex.c

echo ================================================================
echo   Building Kyber-512 (KYBER_K=2)
echo ================================================================
%CC% %BASE_FLAGS% -DKYBER_K=2 %INCLUDES% %SRCS% -o kyber512_test.exe -ladvapi32
if %errorlevel% neq 0 ( echo BUILD FAILED for Kyber-512 & exit /b 1 )

echo ================================================================
echo   Building Kyber-768 (KYBER_K=3)
echo ================================================================
%CC% %BASE_FLAGS% -DKYBER_K=3 %INCLUDES% %SRCS% -o kyber768_test.exe -ladvapi32
if %errorlevel% neq 0 ( echo BUILD FAILED for Kyber-768 & exit /b 1 )

echo ================================================================
echo   Building Kyber-1024 (KYBER_K=4)
echo ================================================================
%CC% %BASE_FLAGS% -DKYBER_K=4 %INCLUDES% %SRCS% -o kyber1024_test.exe -ladvapi32
if %errorlevel% neq 0 ( echo BUILD FAILED for Kyber-1024 & exit /b 1 )

echo.
echo ================================================================
echo   Running Kyber-512 Analysis
echo ================================================================
kyber512_test.exe
rename benchmark_results.csv benchmark_kyber512.csv 2>nul

echo.
echo ================================================================
echo   Running Kyber-768 Analysis
echo ================================================================
kyber768_test.exe
rename benchmark_results.csv benchmark_kyber768.csv 2>nul

echo.
echo ================================================================
echo   Running Kyber-1024 Analysis
echo ================================================================
kyber1024_test.exe
rename benchmark_results.csv benchmark_kyber1024.csv 2>nul

echo.
echo ================================================================
echo   COMPARISON COMPLETE
echo   CSV files generated:
echo     - benchmark_kyber512.csv
echo     - benchmark_kyber768.csv
echo     - benchmark_kyber1024.csv
echo ================================================================
