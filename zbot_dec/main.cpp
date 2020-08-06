#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>

#include <paramkit.h> // include ParamKit header (https://github.com/hasherezade/paramkit)

using namespace paramkit;

#include "zbot_common.h"
#include "util.h"

#define PARAM_RC4KEY "key"
#define PARAM_RC4CTX "ctx"
#define PARAM_INFILE "in"

#define PARAM_VCRYPT "vcrypt"
#define PARAM_CRC32 "crc32"

const char g_StrXorKey[] = "fgK#I6#D!NtdI#!J";

typedef struct {
    char rc4key[MAX_PATH];
    char rc4_ctx_file[MAX_PATH];
    char input_file[MAX_PATH];
    bool is_visualcrypt;
    bool is_crc32;
} t_params_struct;


class DecoderParams : public Params
{
public:
    DecoderParams()
        : Params()
    {
        this->addParam(new StringParam(PARAM_RC4KEY, false));
        this->getParam(PARAM_RC4KEY)->typeDescStr = "RC4 Key";
        this->setInfo(PARAM_RC4KEY, "RC4 key");

        this->addParam(new StringParam(PARAM_RC4CTX, false));
        this->setInfo(PARAM_RC4CTX, "RC4 context");
        this->getParam(PARAM_RC4CTX)->typeDescStr = "file";

        this->addParam(new StringParam(PARAM_INFILE, true));
        this->setInfo(PARAM_INFILE, "Input file (encrypted)");
        this->getParam(PARAM_INFILE)->typeDescStr = "file";

        this->addParam(new BoolParam(PARAM_VCRYPT, false));
        this->setInfo(PARAM_VCRYPT, "Apply Visual Crypt after RC4");

        this->addParam(new BoolParam(PARAM_CRC32, false));
        this->setInfo(PARAM_CRC32, "Apply CRC32");
    }

    bool fillStruct(t_params_struct &paramsStruct)
    {
        StringParam *strP = dynamic_cast<StringParam*>(this->getParam(PARAM_RC4KEY));
        if (strP) strP->copyToCStr(paramsStruct.rc4key, sizeof(paramsStruct.rc4key));

        strP = dynamic_cast<StringParam*>(this->getParam(PARAM_RC4CTX));
        if (strP) strP->copyToCStr(paramsStruct.rc4_ctx_file, sizeof(paramsStruct.rc4_ctx_file));

        strP = dynamic_cast<StringParam*>(this->getParam(PARAM_INFILE));
        if (strP) strP->copyToCStr(paramsStruct.input_file, sizeof(paramsStruct.input_file));

        BoolParam *myBool = dynamic_cast<BoolParam*>(this->getParam(PARAM_VCRYPT));
        if (myBool) paramsStruct.is_visualcrypt = myBool->value;

        myBool = dynamic_cast<BoolParam*>(this->getParam(PARAM_CRC32));
        if (myBool) paramsStruct.is_crc32 = myBool->value;
        return true;
    }

    virtual bool hasRequiredFilled()
    {
        if (!Params::hasRequiredFilled()) return false;

        if (isRC4() || !this->isSet(PARAM_VCRYPT) || !this->isSet(PARAM_CRC32)) {
            return true;
        }
        std::cout << "No algorithm selected!\n";
        return false;
    }

    bool isRC4()
    {
        if (this->isSet(PARAM_RC4CTX) || this->isSet(PARAM_RC4KEY)) {
            return true;
        }
        return false;
    }
};

char *decode_cstr(char* in_buf, char* out_buf, int length)
{
    for (size_t i = 0; i != length; ++i)
        out_buf[i] = g_StrXorKey[i % 16] ^ in_buf[i];
    return out_buf;
}

wchar_t *decode_wstring(const wchar_t *in_buf, wchar_t *out_buf, int length)
{
    for (size_t i = 0; i != length; ++i)
        out_buf[i] = wchar_t(g_StrXorKey[i % 16]) ^ in_buf[i];
    return out_buf;
}


int main(int argc, char *argv[])
{
    DecoderParams params;
    if (argc < 2 || !params.parse(argc, argv) || !params.hasRequiredFilled()) {
        std::cout << "Silent Night Zbot - decryptor for encrypted elements\n";
        std::cout << "Args: <params...>\n";
        params.info();
        return 0;
    }

#ifdef _DEBUG
    std::cout << "[+] Loaded!\n";
#endif

    t_params_struct pstruct = { 0 };
    params.fillStruct(pstruct);

    char *filepath = pstruct.input_file;
    size_t enc_size = 0;
    BYTE *enc_buf = util::read_from_file(filepath, enc_size);
    if (enc_size == 0) {
        std::cout << "Could not read file: " << filepath << "\n";
        return -1;
    }
    std::cout << "Loaded bytes: " << std::hex << enc_size << "\n";

    BYTE ctx[RC4_CTX_SIZE] = { 0 };

    char *key = pstruct.rc4key;
    size_t key_len = strlen(pstruct.rc4key);
    BYTE* out_buf = nullptr;

    if (params.isRC4()) {
        if (key_len > 0) {
            std::cout << "Key: " << pstruct.rc4key << "\nlen:" << std::hex << "0x" << key_len << "\n";
            rc4Init((BYTE*)key, key_len, (RC4KEY*)ctx);
        }
        else {
            size_t ctx_size = 0;
            BYTE *buf = util::read_from_file(pstruct.rc4_ctx_file, ctx_size);
            if (ctx_size >= RC4_CTX_SIZE) {
                memcpy(ctx, buf, RC4_CTX_SIZE);
            }
            util::free_buf(buf);
            std::cout << "Decoding with dumped context\n";
        }

        out_buf = (BYTE*)rc4(enc_buf, enc_size, (RC4KEY*)ctx);
        if (out_buf) {
            enc_buf = out_buf;
        }
        else {
            std::cout << "[-] RC4 decrypt failed!\n";
        }
    }

    if (pstruct.is_visualcrypt) {
        visualDecrypt(enc_buf, enc_size);
    }

    if (pstruct.is_crc32) {
        DWORD crc = crc32Hash(enc_buf, enc_size);
        std::cout << "CRC32: " << std::hex << crc << "\n";
    }

    if (out_buf) {
        std::string out_file = std::string(filepath) + "_dec.bin";

        if (util::dump_to_file(out_file.c_str(), out_buf, enc_size)) {
            std::cout << "[+] Saved to: " << out_file << "\n";
        }
    }
    return 0;
}
