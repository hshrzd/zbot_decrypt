#pragma once

#include <windows.h>

namespace util {
    inline BYTE* alloc_buf(const size_t r_size)
    {
        return new BYTE[r_size];
    }

    inline void free_buf(BYTE* buf)
    {
        free(buf);
    }

    bool dump_to_file(IN const char *out_path, IN PBYTE dump_data, IN size_t dump_size);

    BYTE* read_from_file(IN const char *in_path, IN OUT size_t &read_size);
};
