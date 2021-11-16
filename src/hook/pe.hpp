#pragma once
#include <vector>

#include <Windows.h>
#include <pshpack1.h>

namespace hook {
struct ImportSymbol {
    size_t rva; // RVA of IAT entry
    void** iat; // IAT entry
    WORD   hint;
    union {
        struct {
            WORD by_name; // if 0, import with ordinal
            WORD ordinal;
        } ordinal;
        const char* name;
    };
};

// class for getting information from pe file
class PEFile {
  private:
    static auto map_image(const wchar_t* iFileName) -> BYTE*;

    template <class T>
    auto get_data_pointer(const size_t rva) const -> T {
        return reinterpret_cast<T>(load_base + rva);
    }

    bool                  is_need_free;
    BYTE*                 load_base;
    IMAGE_DOS_HEADER*     dos_header;
    IMAGE_NT_HEADERS*     nt_headers;
    IMAGE_SECTION_HEADER* section_table;

  public:
    auto get_load_base() const -> BYTE*;
    auto get_dos_header() const -> IMAGE_DOS_HEADER*;
    auto get_nt_headers() const -> IMAGE_NT_HEADERS*;
    auto get_file_header() const -> IMAGE_FILE_HEADER*;
    auto get_optional_header() const -> IMAGE_OPTIONAL_HEADER*;
    auto get_section_header(int index) const -> IMAGE_SECTION_HEADER*;

    struct DirectoryEntry {
        const BYTE* address;
        size_t      size;
    };
    auto get_dir_entry(int index) const -> DirectoryEntry;
    auto get_import_dir_entry() const -> const IMAGE_IMPORT_DESCRIPTOR*;
    auto get_import_dll_names() const -> std::vector<const char*>;
    auto get_export_dir_entry() const -> const IMAGE_EXPORT_DIRECTORY*;
    auto get_import_symbols(const char* dll_name) const -> std::vector<ImportSymbol>;
    auto hook_import_symbol(const void* original, const void* inject) -> void**;
    auto hook_export_symbol(const char* func, const void* inject) -> void*;

    explicit PEFile(const wchar_t* path); // use getLoadBase() for result
    explicit PEFile(HMODULE module_handle);
    virtual ~PEFile();
};
} // namespace wrapper
#include <poppack.h>
