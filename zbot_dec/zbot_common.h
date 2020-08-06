#pragma once

#include <Windows.h>

#define RC4_CTX_SIZE 0x102

typedef struct
{
    BYTE state[256];
    BYTE x;
    BYTE y;
} RC4KEY;

BYTE* rc4(BYTE *buffer, DWORD size, RC4KEY *key);
void rc4Init(const void *binKey, WORD binKeySize, RC4KEY *key);
void rc4Full(const void *binKey, WORD binKeySize, void *buffer, DWORD size);

BYTE* visualDecrypt(BYTE *buffer, DWORD size);

DWORD crc32Hash(const void *data, DWORD size);
