#include <array>

#include <Windows.h>

#include <TlHelp32.h>

#include "error.hpp"
#include "pe.hpp"
#include "hook.hpp"

namespace hook {
namespace {
auto WINAPI mLoadLibraryA(const char* const i_dll_name) -> HMODULE;
auto WINAPI mLoadLibraryW(const wchar_t* const i_dll_name) -> HMODULE;
auto WINAPI mLoadLibraryExA(const char* const i_dll_name, const HANDLE i_reserved, const DWORD i_flags) -> HINSTANCE;
auto WINAPI mLoadLibraryExW(const wchar_t* i_dll_name, HANDLE i_reserved, DWORD i_flags) -> HINSTANCE;
auto WINAPI mGetProcAddress(HMODULE i_module_handle, const char* i_func_name) -> FARPROC;

auto targets = std::vector<Symbol>{
    {"kernel32.dll", "LoadLibraryA", &mLoadLibraryA},
    {"kernel32.dll", "LoadLibraryW", &mLoadLibraryW},
    {"kernel32.dll", "LoadLibraryExA", &mLoadLibraryExA},
    {"kernel32.dll", "LoadLibraryExW", &mLoadLibraryExW},
    {"kernel32.dll", "GetProcAddress", &mGetProcAddress},
};

auto WINAPI mLoadLibraryA(const char* const i_dll_name) -> HMODULE {
    const auto module_handle = LoadLibraryA(i_dll_name);
    if(module_handle) {
        hook_imports(PEFile(module_handle), true);
    }
    return module_handle;
}
auto WINAPI mLoadLibraryW(const wchar_t* const i_dll_name) -> HMODULE {
    const auto module_handle = LoadLibraryW(i_dll_name);
    if(module_handle) {
        hook_imports(PEFile(module_handle), true);
    }
    return module_handle;
}
auto WINAPI mLoadLibraryExA(const char* const i_dll_name, const HANDLE i_reserved, const DWORD i_flags) -> HINSTANCE {
    const auto module_handle = LoadLibraryExA(i_dll_name, i_reserved, i_flags);
    if(module_handle && (i_flags & LOAD_LIBRARY_AS_DATAFILE) == 0) {
        hook_imports(PEFile(module_handle), true);
    }
    return module_handle;
}
auto WINAPI mLoadLibraryExW(const wchar_t* i_dll_name, HANDLE i_reserved, DWORD i_flags) -> HINSTANCE {
    const auto module_handle = LoadLibraryExW(i_dll_name, i_reserved, i_flags);
    if(module_handle && (i_flags & LOAD_LIBRARY_AS_DATAFILE) == 0) {
        hook_imports(PEFile(module_handle), true);
    }
    return module_handle;
}
auto WINAPI mGetProcAddress(HMODULE i_module_handle, const char* i_func_name) -> FARPROC {
    const auto r = GetProcAddress(i_module_handle, i_func_name);
    for(const auto& t : targets) {
        if(t.original == r) {
            return reinterpret_cast<FARPROC>(t.inject);
        }
    }
    return r;
}
auto init_symbol_original(Symbol& s) -> void {
    const auto a = GetModuleHandleA(s.file);
    ASSERT(a != 0, "module not found");
    s.original = GetProcAddress(a, s.func);
}
} // namespace

auto init(const Symbol symbols[], size_t size) -> void {
    targets.reserve(targets.size() + size);
    for(auto i = size_t(0); i < size; i += 1) {
        targets.emplace_back(symbols[i]);
    }
    for(auto& t : targets) {
        init_symbol_original(t);
    }
}
auto hook_imports(PEFile pe, const bool hook, const bool is_self) -> bool {
    for(const auto& t : targets) {
        if(!is_self) {
            pe.hook_import_symbol(hook ? t.original : t.inject, hook ? t.inject : t.original);
        } else if(t.slave != nullptr) {
            const auto o = GetProcAddress(GetModuleHandleA(t.slave), t.func);
            const auto i = GetProcAddress(GetModuleHandleA(t.file), t.func);
            pe.hook_import_symbol(hook ? o : i, hook ? i : o);
        }
    }
    return true;
}
auto hook_all_imports(const HMODULE self, const bool hook) -> bool {
    auto snapshot     = INVALID_HANDLE_VALUE;
    auto module_entry = MODULEENTRY32W{sizeof(MODULEENTRY32W), 0};
    snapshot          = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    for(auto is_next = Module32FirstW(snapshot, &module_entry); is_next; is_next = Module32NextW(snapshot, &module_entry)) {
        hook_imports(PEFile(module_entry.hModule), hook, module_entry.hModule == self);
    }
    if(snapshot != INVALID_HANDLE_VALUE) {
        CloseHandle(snapshot);
    }
    return true;
}
auto hook_exports(const char* file, const char* func, const void* inject) -> void* {
    const auto m = GetModuleHandleA(file);
    if (m == NULL) {
        return nullptr;
    }
    return PEFile(m).hook_export_symbol(func, inject);
}
auto hook_all_exports() -> void {
    for(const auto& t : targets) {
        hook_exports(t.file, t.func, t.inject);
    }
}
auto get_path_from_handle(const HINSTANCE handle) -> std::wstring {
    auto       path        = std::array<wchar_t, MAX_PATH>();
    const auto path_length = GetModuleFileNameW(handle, path.data(), path.size());
    ASSERT(path_length != 0, "failed to locate target file path")
    ASSERT(path_length != MAX_PATH, "path too long")
    return path.data();
}
} // namespace hook