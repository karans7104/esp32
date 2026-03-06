@echo off
echo ============================================
echo   Building Kyber KEM PC Simulation
echo ============================================

set CC=gcc
set CFLAGS=-O2 -Wall -DKYBER_90S -DKYBER_K=2 -DSHA_ACC=0 -DAES_ACC=0 -DINDCPA_KEYPAIR_DUAL=0 -DINDCPA_ENC_DUAL=0 -DINDCPA_DEC_DUAL=0

set INCLUDES=-I..\components\common -I..\components\kem -I..\components\indcpa -I..\components\poly -I..\components\polyvec -I..\components\ntt -I..\components\reduce -I..\components\cbd -I..\components\symmetric -I..\components\aes256ctr -I..\components\fips202 -I..\components\sha2 -I..\components\randombytes -I..\components\verify -I..\components\kex

set SRCS=main_sim.c randombytes_pc.c ..\components\kem\kem.c ..\components\indcpa\indcpa.c ..\components\poly\poly.c ..\components\polyvec\polyvec.c ..\components\ntt\ntt.c ..\components\reduce\reduce.c ..\components\cbd\cbd.c ..\components\symmetric\symmetric-aes.c ..\components\symmetric\symmetric-shake.c ..\components\aes256ctr\aes256ctr.c ..\components\fips202\fips202.c ..\components\sha2\sha256.c ..\components\sha2\sha512.c ..\components\verify\verify.c ..\components\kex\kex.c

echo Compiling...
%CC% %CFLAGS% %INCLUDES% %SRCS% -o kyber_sim.exe -ladvapi32

if %errorlevel% == 0 (
    echo Build successful!
    echo.
    echo Running simulation...
    echo ============================================
    kyber_sim.exe
) else (
    echo Build FAILED!
    exit /b 1
)
