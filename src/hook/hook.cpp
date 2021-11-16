#include <array>

#include <Windows.h>

#include <TlHelp32.h>

#include "error.hpp"
#include "hook.hpp"
#include "pe.hpp"

namespace hook {
namespace {
auto WINAPI mLoadLibraryA(const char* i_dll_name) -> HMODULE;
auto WINAPI mLoadLibraryW(const wchar_t* i_dll_name) -> HMODULE;
auto WINAPI mLoadLibraryExA(const char* i_dll_name, HANDLE i_reserved, DWORD i_flags) -> HINSTANCE;
auto WINAPI mLoadLibraryExW(const wchar_t* i_dll_name, HANDLE i_reserved, DWORD i_flags) -> HINSTANCE;
auto WINAPI mGetProcAddress(HMODULE i_module_handle, const char* i_func_name) -> FARPROC;
auto WINAPI mCreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) -> BOOL;
auto WINAPI mCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) -> BOOL;

auto targets = std::vector<Symbol>{
    {"kernel32.dll", "LoadLibraryA", &mLoadLibraryA},
    {"kernel32.dll", "LoadLibraryW", &mLoadLibraryW},
    {"kernel32.dll", "LoadLibraryExA", &mLoadLibraryExA},
    {"kernel32.dll", "LoadLibraryExW", &mLoadLibraryExW},
    {"kernel32.dll", "GetProcAddress", &mGetProcAddress},
    {"kernel32.dll", "CreateProcessA", &mCreateProcessA},
    {"kernel32.dll", "CreateProcessW", &mCreateProcessW},
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
auto WINAPI mLoadLibraryExW(const wchar_t* const i_dll_name, const HANDLE i_reserved, const DWORD i_flags) -> HINSTANCE {
    const auto module_handle = LoadLibraryExW(i_dll_name, i_reserved, i_flags);
    if(module_handle && (i_flags & LOAD_LIBRARY_AS_DATAFILE) == 0) {
        hook_imports(PEFile(module_handle), true);
    }
    return module_handle;
}
auto WINAPI mGetProcAddress(const HMODULE i_module_handle, const char* const i_func_name) -> FARPROC {
    const auto r = GetProcAddress(i_module_handle, i_func_name);
    for(const auto& t : targets) {
        if(t.original == r) {
            return reinterpret_cast<FARPROC>(t.inject);
        }
    }
    return r;
}
auto WINAPI mCreateProcessA(const LPCSTR lpApplicationName, const LPSTR lpCommandLine, const LPSECURITY_ATTRIBUTES lpProcessAttributes, const LPSECURITY_ATTRIBUTES lpThreadAttributes, const BOOL bInheritHandles, const DWORD dwCreationFlags, const LPVOID lpEnvironment, const LPCSTR lpCurrentDirectory, const LPSTARTUPINFOA lpStartupInfo, const LPPROCESS_INFORMATION lpProcessInformation) -> BOOL {
    const auto resume = !bool(dwCreationFlags & CREATE_SUSPENDED);
    const auto f      = dwCreationFlags | CREATE_SUSPENDED;
    const auto r      = CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, f, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    if(r == TRUE) {
        inject(lpProcessInformation->hProcess);
        if(resume) {
            ResumeThread(lpProcessInformation->hThread);
        }
    }
    return r;
}
auto WINAPI mCreateProcessW(const LPCWSTR lpApplicationName, const LPWSTR lpCommandLine, const LPSECURITY_ATTRIBUTES lpProcessAttributes, const LPSECURITY_ATTRIBUTES lpThreadAttributes, const BOOL bInheritHandles, const DWORD dwCreationFlags, const LPVOID lpEnvironment, const LPCWSTR lpCurrentDirectory, const LPSTARTUPINFOW lpStartupInfo, const LPPROCESS_INFORMATION lpProcessInformation) -> BOOL {
    const auto resume = !bool(dwCreationFlags & CREATE_SUSPENDED);
    const auto f      = dwCreationFlags | CREATE_SUSPENDED;
    const auto r      = CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, f, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    if(r == TRUE) {
        inject(lpProcessInformation->hProcess);
        if(resume) {
            ResumeThread(lpProcessInformation->hThread);
        }
    }
    return r;
}
auto init_symbol_original(Symbol& s) -> void {
    const auto a = GetModuleHandleA(s.file);
    ASSERT(a != 0, "module not found");
    s.original = GetProcAddress(a, s.func);
}
auto find_original_function(const auto f) -> decltype(f) {
    for(const auto& t : targets) {
        if(t.inject == f && t.original != nullptr) {
            return (decltype(f))t.original;
        }
    }
    return f;
}
} // namespace

auto inject(const HANDLE process) -> void {
    auto self = HMODULE();
    ASSERT(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)(&inject), &self) != 0, "failed to locate self handle")

    const auto self_path = get_path_from_handle(self);

    const auto size_bytes = (self_path.size() + 1) * sizeof(self_path[0]);
    const auto remote_mem = VirtualAllocEx(process, NULL, size_bytes, MEM_COMMIT, PAGE_READWRITE);
    ASSERT(remote_mem != NULL, "error at VirtualAllocEx()")

    auto written = SIZE_T(0);
    ASSERT(WriteProcessMemory(process, remote_mem, self_path.data(), size_bytes, &written) != FALSE, "error at WriteProcessMemory()")

    const auto loadlibrary_pointer = find_original_function(LoadLibraryW);

    auto       thread_id     = DWORD(0);
    const auto thread_handle = CreateRemoteThread(process, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(loadlibrary_pointer), remote_mem, 0, &thread_id);
    ASSERT(thread_handle != NULL, "dll not found")

    WaitForSingleObject(thread_handle, INFINITE);
    auto exit_code = DWORD(0);
    GetExitCodeThread(thread_handle, &exit_code);

    CloseHandle(thread_handle);
    VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
}
auto init(const Symbol symbols[], size_t size) -> void {
    targets.reserve(targets.size() + size);
    for(auto i = size_t(0); i < size; i += 1) {
        targets.emplace_back(symbols[i]);
    }
    for(auto& t : targets) {
        init_symbol_original(t);
    }
}
auto hook_imports(PEFile pe, const bool hook) -> bool {
    for(const auto& t : targets) {
        pe.hook_import_symbol(hook ? t.original : t.inject, hook ? t.inject : t.original);
    }
    return true;
}
auto hook_all_imports(const HMODULE self, const bool hook) -> bool {
    auto snapshot     = INVALID_HANDLE_VALUE;
    auto module_entry = MODULEENTRY32W{sizeof(MODULEENTRY32W), 0};
    snapshot          = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    for(auto is_next = Module32FirstW(snapshot, &module_entry); is_next; is_next = Module32NextW(snapshot, &module_entry)) {
        if(module_entry.hModule == self) {
            continue;
        }
        hook_imports(PEFile(module_entry.hModule), hook);
    }
    if(snapshot != INVALID_HANDLE_VALUE) {
        CloseHandle(snapshot);
    }
    return true;
}
auto hook_exports(const char* file, const char* func, const void* inject) -> void* {
    const auto m = GetModuleHandleA(file);
    if(m == NULL) {
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
