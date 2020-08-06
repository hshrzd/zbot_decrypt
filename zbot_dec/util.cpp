#include "util.h"

bool util::dump_to_file(IN const char *out_path, IN PBYTE dump_data, IN size_t dump_size)
{
    if (!out_path || !dump_data || !dump_size) return false;

    HANDLE file = CreateFileA(out_path, GENERIC_WRITE, FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {

        return false;
    }
    DWORD written_size = 0;
    bool is_dumped = false;
    if (WriteFile(file, dump_data, (DWORD)dump_size, &written_size, nullptr)) {
        is_dumped = true;
    }
    CloseHandle(file);
    return is_dumped;
}

//load file content using ReadFile
BYTE* util::read_from_file(IN const char *in_path, IN OUT size_t &read_size)
{
    HANDLE file = CreateFileA(in_path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        return nullptr;
    }
    size_t r_size = static_cast<size_t>(GetFileSize(file, 0));
    if (read_size != 0 && read_size <= r_size) {
        r_size = read_size;
    }
    BYTE *buffer = alloc_buf(r_size);
    if (buffer == nullptr) {
        return nullptr;
    }
    DWORD out_size = 0;
    if (!ReadFile(file, buffer, r_size, &out_size, nullptr)) {

        free_buf(buffer);
        buffer = nullptr;
        read_size = 0;
    }
    else {
        read_size = r_size;
    }
    CloseHandle(file);
    return buffer;
}

