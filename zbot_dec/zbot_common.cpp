#include "zbot_common.h"
#include <iostream>

static DWORD crc32table[256];
bool crc32Intalized = false;

DWORD crc32Hash(const void *data, DWORD size)
{
    if (crc32Intalized == false)
    {
        register DWORD crc;
        for (register DWORD i = 0; i < 256; i++)
        {
            crc = i;
            for (register DWORD j = 8; j > 0; j--)
            {
                if (crc & 0x1)crc = (crc >> 1) ^ 0xEDB88320L;
                else crc >>= 1;
            }
            crc32table[i] = crc;
        }

        crc32Intalized = true;
    }

    register DWORD cc = 0xFFFFFFFF;
    for (register DWORD i = 0; i < size; i++)cc = (cc >> 8) ^ crc32table[(((LPBYTE)data)[i] ^ cc) & 0xFF];
    return ~cc;
}

#define swap_byte(a, b) {swapByte = a; a = b; b = swapByte;}

void rc4Init(const void *binKey, WORD binKeySize, RC4KEY *key)
{
    register BYTE swapByte;
    register BYTE index1 = 0, index2 = 0;
    LPBYTE state = &key->state[0];
    register WORD i;

    key->x = 0;
    key->y = 0;

    for (i = 0; i < 256; i++)state[i] = i;
    for (i = 0; i < 256; i++)
    {
        index2 = (((LPBYTE)binKey)[index1] + state[i] + index2) & 0xFF;
        swap_byte(state[i], state[index2]);
        if (++index1 == binKeySize)index1 = 0;
    }
}

BYTE* rc4(BYTE *buffer, DWORD size, RC4KEY *key)
{

    register BYTE swapByte;
    register BYTE x = key->x;
    register BYTE y = key->y;
    LPBYTE state = &key->state[0];

    for (register DWORD i = 0; i < size; i++)
    {
        x = (x + 1) & 0xFF;
        y = (state[x] + y) & 0xFF;
        swap_byte(state[x], state[y]);
        ((LPBYTE)buffer)[i] ^= state[(state[x] + state[y]) & 0xFF];
    }

    key->x = x;
    key->y = y;

    return buffer;
}

void rc4Full(const void *binKey, WORD binKeySize, void *buffer, DWORD size)
{
    RC4KEY key;
    rc4Init(binKey, binKeySize, &key);
    rc4((BYTE*)buffer, size, &key);
}

BYTE* visualDecrypt(BYTE *buffer, DWORD size)
{
    if (size == 0) return buffer;

    for (DWORD i = size - 1; i > 0; i--)
        ((LPBYTE)buffer)[i] ^= ((LPBYTE)buffer)[i - 1];

    return buffer;
}

