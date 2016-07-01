#ifndef ENCRYPTIONLIBRARY_H
#define ENCRYPTIONLIBRARY_H
#include <stdint.h>

#define P2PI_TRUST_N        4611685846628697223ULL
#define P2PI_TRUST_E        5ULL

void StringToPublicNED(const char *str, uint64_t &n, uint64_t &e, uint64_t &d);
void PublicEncryptDecrypt(uint64_t &data, uint64_t e_or_d, uint64_t n);
void GenerateRandomString(uint8_t *str, uint32_t length, uint64_t sequence);
void PrivateEncryptDecrypt(uint8_t *str, uint32_t length, uint64_t sequence);
uint64_t GenerateRandomValue();
uint32_t AuthenticationChecksum(uint32_t sec, const char *str, uint64_t e, uint64_t n);

#endif

