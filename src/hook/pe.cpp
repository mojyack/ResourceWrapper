#include <fstream>
#include <iostream>
#include <vector>

#include "error.hpp"
#include "pe.hpp"

namespace {
template <class T>
auto read_file(const wchar_t* const path) -> std::vector<T> {
    auto       f = std::fstream(path, std::ios::binary | std::ios::ate);
    const auto s = f.tellg();
    f.seekg(0, std::ios::beg);
    const auto mod = (s % sizeof(T)) != 0;
    auto       b   = std::vector<T>(s / sizeof(T) + (mod ? 1 : 0));
    f.read(reinterpret_cast<char*>(b.data()), s);
    return b;
}
} // namespace

namespace hook {
auto PEFile::map_image(const wchar_t* const path) -> BYTE* {
    const auto file = read_file<BYTE>(path);

    const auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(file.data());
    ASSERT(dos_header->e_magic == *reinterpret_cast<const WORD*>("MZ") && dos_header->e_lfanew != 0, "invalid dos header")

    const auto nt_header = reinterpret_cast<const IMAGE_NT_HEADERS*>(&file[dos_header->e_lfanew]);
    ASSERT(nt_header->Signature == *reinterpret_cast<const size_t*>("PE\0\0") && nt_header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC, "invalid nt header")

    const auto section_table = reinterpret_cast<const IMAGE_SECTION_HEADER*>(nt_header + 1);
    const auto r             = reinterpret_cast<BYTE*>(VirtualAlloc(NULL, nt_header->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE));
    ASSERT(r != NULL, "error at VirtualAlloc()")

    memcpy(r, file.data(), nt_header->OptionalHeader.SizeOfHeaders);
    for(int i = 0; i < nt_header->FileHeader.NumberOfSections; i++) {
        const auto& s = section_table[i];
        if(s.PointerToRawData) {
            memcpy(&r[s.VirtualAddress], &file[s.PointerToRawData], s.SizeOfRawData);
        }
    }
    return r;
}
auto PEFile::get_load_base() const -> BYTE* {
    return load_base;
}
auto PEFile::get_dos_header() const -> IMAGE_DOS_HEADER* {
    return dos_header;
}
auto PEFile::get_nt_headers() const -> IMAGE_NT_HEADERS* {
    return nt_headers;
}
auto PEFile::get_file_header() const -> IMAGE_FILE_HEADER* {
    return &nt_headers->FileHeader;
}
auto PEFile::get_optional_header() const -> IMAGE_OPTIONAL_HEADER* {
    return &nt_headers->OptionalHeader;
}
auto PEFile::get_section_header(const int index) const -> IMAGE_SECTION_HEADER* {
    ASSERT(index >= 0 && index < get_file_header()->NumberOfSections, "index out of range")
    return &section_table[index];
}
auto PEFile::get_dir_entry(const int index) const -> DirectoryEntry {
    ASSERT(index >= 0 && index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES, "index out of range")
    const auto& d = get_optional_header()->DataDirectory[index];
    if(d.VirtualAddress && d.Size) {
        return {load_base + d.VirtualAddress, d.Size};
    } else {
        return {nullptr, 0};
    }
}
auto PEFile::get_import_dir_entry() const -> const IMAGE_IMPORT_DESCRIPTOR* {
    return reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(get_dir_entry(IMAGE_DIRECTORY_ENTRY_IMPORT).address);
}
auto PEFile::get_import_dll_names() const -> std::vector<const char*> {
    auto       r       = std::vector<const char*>();
    const auto imports = get_import_dir_entry();
    for(int i = 0; imports[i].FirstThunk != 0; i += 1) {
        r.emplace_back(get_data_pointer<const char*>(imports[i].Name));
    }
    return r;
}
auto PEFile::get_export_dir_entry() const -> const IMAGE_EXPORT_DIRECTORY* {
    return reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(get_dir_entry(IMAGE_DIRECTORY_ENTRY_EXPORT).address);
}

auto PEFile::get_import_symbols(const char* dll_name) const -> std::vector<ImportSymbol> {
    auto       r       = std::vector<ImportSymbol>();
    const auto imports = get_import_dir_entry();
    if(!imports[0].OriginalFirstThunk && !is_need_free) {
        return r;
    }
    for(int i = 0; imports[i].FirstThunk != 0; i += 1) {
        const auto& d = imports[i];
        if(_stricmp(dll_name, get_data_pointer<const char*>(d.Name)) != 0) {
            continue;
        }
        const auto iat_pointer = get_data_pointer<IMAGE_THUNK_DATA*>(d.FirstThunk);
        const auto int_pointer = d.OriginalFirstThunk ? get_data_pointer<IMAGE_THUNK_DATA*>(d.OriginalFirstThunk) : iat_pointer;
        for(size_t i = 0;; i += 1) {
            const auto address = (reinterpret_cast<size_t*>(int_pointer))[i];
            if(address == 0) {
                break;
            }
            if(address >= get_optional_header()->SizeOfImage) {
                continue;
            }
            const auto rva = d.FirstThunk + sizeof(DWORD) * i;
            const auto iat = reinterpret_cast<void**>(&iat_pointer[i]);
            if(IMAGE_SNAP_BY_ORDINAL(reinterpret_cast<size_t*>(int_pointer)[i])) {
                const auto ordinal = static_cast<WORD>(IMAGE_ORDINAL(address));
                r.emplace_back(ImportSymbol{.rva = rva, .iat = iat, .hint = 0, .ordinal = {.by_name = 0, .ordinal = ordinal}});
            } else {
                const auto name = get_data_pointer<IMAGE_IMPORT_BY_NAME*>(address);
                r.emplace_back(ImportSymbol{.rva = rva, .iat = iat, .hint = name->Hint, .name = reinterpret_cast<char*>(name->Name)});
            }
        }
    }
    return r;
}
auto PEFile::hook_import_symbol(const void* const original, const void* const inject) -> void** {
    auto       r       = (void**)(nullptr);
    const auto imports = get_import_dir_entry();
    if(imports == nullptr) {
        return nullptr;   
    }
    for(int i = 0; imports[i].FirstThunk != 0; i += 1) {
        const auto& d   = imports[i];
        const auto  iat = get_data_pointer<void**>(d.FirstThunk);
        for(int i = 0; iat[i] != 0; i += 1) {
            if(iat[i] == reinterpret_cast<FARPROC>(original)) {
                auto protect = DWORD(0);
                VirtualProtect(&iat[i], sizeof(FARPROC), PAGE_READWRITE, &protect);
                r      = &iat[i];
                iat[i] = reinterpret_cast<FARPROC>(inject);
                VirtualProtect(&iat[i], sizeof(FARPROC), protect, &protect);
            }
        }
    }
    return r;
}
auto PEFile::hook_export_symbol(const char* const func, const void* const inject) -> void* {
    auto       r       = (void*)(nullptr);
    const auto exports = get_export_dir_entry();
    if (exports == nullptr) {
        return nullptr;
    }
    const auto name_offset_array = get_data_pointer<DWORD*>(exports->AddressOfNames);
    const auto ordinal_array = get_data_pointer<WORD*>(exports->AddressOfNameOrdinals);
    const auto function_offset_array = get_data_pointer<DWORD*>(exports->AddressOfFunctions);
    for (auto i = DWORD(0); i < exports->NumberOfFunctions; i += 1) {
        const auto name = get_data_pointer<const char*>(name_offset_array[i]);
        if(_stricmp(func, name) != 0) {
            continue;
        }
        const auto current_ordinal = ordinal_array[i];
        const auto current_function_offset = function_offset_array + current_ordinal;
        const auto hook_offset = static_cast<const BYTE*>(inject) - load_base;

        auto protect = DWORD(0);
        VirtualProtect(current_function_offset, sizeof(DWORD), PAGE_READWRITE, &protect);
        r = load_base + *current_function_offset;
        *current_function_offset = hook_offset;
        VirtualProtect(current_function_offset, sizeof(DWORD), protect, &protect);
        break;
    }
    return r;
}
PEFile::PEFile(const wchar_t* const path) : is_need_free(true) {
    load_base     = map_image(path);
    dos_header    = reinterpret_cast<IMAGE_DOS_HEADER*>(load_base);
    nt_headers    = reinterpret_cast<IMAGE_NT_HEADERS*>(load_base + dos_header->e_lfanew);
    section_table = reinterpret_cast<IMAGE_SECTION_HEADER*>(nt_headers + 1);
}
PEFile::PEFile(const HMODULE module_handle) : is_need_free(false) {
    dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(module_handle);
    ASSERT(!IsBadReadPtr(dos_header, sizeof(IMAGE_DOS_HEADER)) && dos_header->e_magic == *reinterpret_cast<const WORD*>("MZ"), "invalid dos header")

    nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<BYTE*>(module_handle) + dos_header->e_lfanew);
    ASSERT(nt_headers->Signature == *reinterpret_cast<const DWORD*>("PE\0\0") && nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC, "invalid nt header")

    section_table = reinterpret_cast<IMAGE_SECTION_HEADER*>(nt_headers + 1);
    load_base     = reinterpret_cast<BYTE*>(module_handle);
    
    if(nt_headers->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) {
        warn("high ASLR enabled");
    }
    if(nt_headers->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
        warn("ASLR enabled");
    }
}

PEFile::~PEFile() {
    if(is_need_free && load_base) {
        VirtualFree(load_base, 0, MEM_RELEASE);
    }
}
} // namespace wrapper
