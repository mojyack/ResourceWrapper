#include <array>
#include <filesystem>
#include <unordered_map>

#include "hook/error.hpp"
#include "hook/hook.hpp"
#include "plugin.hpp"

namespace {
auto atow(const char* str) -> std::wstring {
    const auto len = strlen(str) + 1;
    auto       buf = std::vector<wchar_t>(len);
    mbstowcs(buf.data(), str, len);
    return buf.data();
}
auto wtoa(const wchar_t* str) -> std::string {
    const auto len = (wcslen(str) + 1) * sizeof(wchar_t);
    auto       buf = std::vector<char>(len);
    wcstombs(buf.data(), str, len);
    return buf.data();
}
} // namespace
namespace rw {
extern std::vector<Plugin*> plugins;
namespace {
auto cache          = std::unordered_map<std::wstring, std::wstring>();
auto temporary_path = std::wstring();

auto test_blacklist() -> bool {
    auto path = hook::get_path_from_handle(NULL);
    return path.ends_with(L"\\rundll32.exe");
}
auto disable_aslr() -> void {
    auto buffer = PROCESS_MITIGATION_ASLR_POLICY();
    SetProcessMitigationPolicy(ProcessASLRPolicy, &buffer, sizeof(buffer));
}
auto set_temporary_path() -> void {
    auto       data = std::array<wchar_t, MAX_PATH>();
    const auto len  = GetTempPathW(data.size(), data.data());
    ASSERT(len <= data.size() && len != 0, "GetTempPath() failed")
    temporary_path = data.data();
    temporary_path += L"ResourceWrapper-" + std::to_wstring(GetCurrentProcessId());
}
} // namespace

auto WINAPI mCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) -> HANDLE {
    auto path = std::wstring(lpFileName);
    for(auto& c : path) {
        if(c >= L'A' && c <= L'Z') {
            c += L'a' - L'A';
        }
    }
    if(cache.contains(path)) {
        return get_tempfile(cache[path].data());
    }
    for(auto p : plugins) {
        if(auto r = p->prepare_path(path.data()); r.has_value()) {
            path = std::move(*r);
            break;
        }
    }
    if(const auto r = CreateFileW(path.data(), dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile); r != INVALID_HANDLE_VALUE) {
        return r;
    }

    static auto id  = size_t(0);
    auto        tmp = temporary_path + L"\\" + std::to_wstring(id);
    for(auto p : plugins) {
        if(const auto r = p->create_file(path.data(), tmp.data()); r != INVALID_HANDLE_VALUE) {
            id += 1;
            cache.emplace(path, tmp);
            return r;
        }
    }
    return INVALID_HANDLE_VALUE;
}
auto WINAPI mCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) -> HANDLE {
    const auto w = atow(lpFileName);
    return mCreateFileW(w.data(), dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}
auto WINAPI mGetFileAttributesW(LPCWSTR lpFileName) -> DWORD {
    if(const auto r = GetFileAttributesW(lpFileName); r != -1) {
        return r;
    }
    for(auto p : plugins) {
        if(const auto r = p->get_file_attributes(lpFileName); r != -1) {
            return r;
        }
    }
    return -1;
}
auto WINAPI mGetFileAttributesA(LPCSTR lpFileName) -> DWORD {
    const auto w = atow(lpFileName);
    return mGetFileAttributesW(w.data());
}
auto WINAPI mIsDebuggerPresent() -> BOOL {
    return FALSE;
}
} // namespace rw
extern "C" auto WINAPI DllMain(const HINSTANCE module_handle, const DWORD reason, [[maybe_unused]] const LPVOID reserved) -> BOOL {
    if(rw::test_blacklist()) {
        return TRUE;
    }
    switch(reason) {
    case DLL_PROCESS_ATTACH: {
        static const auto targets = std::array{
            hook::Symbol{"Kernel32.dll", "CreateFileA", &rw::mCreateFileA},
            hook::Symbol{"Kernel32.dll", "CreateFileW", &rw::mCreateFileW},
            hook::Symbol{"Kernel32.dll", "GetFileAttributesA", &rw::mGetFileAttributesA},
            hook::Symbol{"Kernel32.dll", "GetFileAttributesW", &rw::mGetFileAttributesW},
            hook::Symbol{"kernel32.dll", "IsDebuggerPresent", &rw::mIsDebuggerPresent},
        };
        rw::set_temporary_path();
        std::filesystem::create_directory(rw::temporary_path);
        hook::init(targets.data(), targets.size());
        hook::hook_all_imports(module_handle, true);
        hook::hook_all_exports();
        setlocale(LC_ALL, "");
        break;
    }
    case DLL_PROCESS_DETACH:
        hook::hook_all_imports(module_handle, false);
        std::filesystem::remove_all(rw::temporary_path);
        break;
    }
    return TRUE;
}
