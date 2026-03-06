#include <stddef.h>
#include <stdint.h>
#include <windows.h>
#include <wincrypt.h>
#include "randombytes.h"

void esp_randombytes(uint8_t *out, size_t outlen) {
    HCRYPTPROV ctx;
    if (!CryptAcquireContext(&ctx, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        abort();
    }
    if (!CryptGenRandom(ctx, (DWORD)outlen, (BYTE *)out)) {
        abort();
    }
    CryptReleaseContext(ctx, 0);
}
