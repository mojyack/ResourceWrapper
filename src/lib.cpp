#include <array>
#include <filesystem>
#include <unordered_map>

#include "hook/error.hpp"
#include "hook/hook.hpp"
#include "plugin.hpp"

namespace rw {
extern std::vector<Plugin*> plugins;
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
// search functions
auto find_files = std::unordered_map<HANDLE, std::wstring>();
auto prepare_find_result(const HANDLE handle, const wchar_t* file) -> std::optional<std::wstring> {
    const auto p = find_files.find(handle);
    if(p == find_files.end()) {
        return std::nullopt;
    }
    const auto path = *p + "\\" + file;
    for(auto p : plugins) {
        if(const auto r = p->prepare_path(path.data()); r != std::nullopt) {
            return r;
        }
    }
    return std::nullopt;
}
auto WINAPI mFindFirstFileExW(LPCWSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags) -> HANDLE {
    const auto r = FindFirstFileExW(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
    if(r == INVALID_HANDLE_VALUE) {
        return r;
    }
    const auto path   = std::filesystem::path(lpFileName);
    const auto parent = path.parent_path();
    if(path != parent_path) {
        find_files.emplace(r, parent_path.wstring());
    }
    const auto sub = prepare_find_result(r, lpFindFileData->cFileName);
    if(sub.has_value()) {
        ASSERT(sub->size() + 1 <= MAX_PATH)
        std::memcpy(lpFindFileData->cFileName, sub->data(), (sub->size() + 1) * sizeof(wchar_t));
    }
    return r;
}
auto WINAPI mFindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) -> BOOL {
    const auto r = FindNextFileW(hFindFile, lpFindFileData);
    if(r != TRUE) {
        return r;
    }
    const auto sub = prepare_find_result(hFindFile, lpFindFileData->cFileName);
    if(sub.has_value()) {
        ASSERT(sub->size() + 1 <= MAX_PATH)
        std::memcpy(lpFindFileData->cFileName, sub->data(), (sub->size() + 1) * sizeof(wchar_t));
    }
    return r;
}
auto filedata_wtoa(const LPWIN32_FIND_DATAW& filedata) -> LPWIN32_FIND_DATAA {
    auto r = LPWIN32_FIND_DATAA{
        filedata.dwFileAttributes,
        filedata.ftCreationTime,
        filedata.ftLastAccessTime,
        filedata.ftLastWriteTime,
        filedata.nFileSizeHigh,
        filedata.nFileSizeLow,
        filedata.dwReserved0,
        filedata.dwReserved1,
        NULL,
        NULL,
        filedata.dwFileType,
        filedata.dwCreatorType,
        filedata.wFinderFlags,
    };
    const auto namea = wtoa(filedata.cFileName);
    std::memcpy(r.cFileName, namea.data(), namea.size() + 1);
    const auto shorta = wtoa(filedata.cAlternateFileName);
    std::memcpy(r.cAlternateFileName, shorta.data(), shorta.size() + 1);
    return r;
}
auto WINAPI mFindFirstFileExA(LPCSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags) -> HANDLE {
    const auto w        = atow(lpFileName);
    auto       filedata = LPWIN32_FIND_DATAW();
    const auto r        = mFindFirstFileExW(w.data(), fInfoLevelId, &filedata, fSearchOp, lpSearchFilter, dwAdditionalFlags);
    if(r == INVALID_HANDLE_VALUE) {
        return r;
    }
    *lpFindFileData = filedata_wtoa(filedata);
    return r;
} // namespace
auto WINAPI mFindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData) -> BOOL {
    auto       filedata = LPWIN32_FIND_DATAW();
    const auto r        = mFindNextFileW(hFindFile, &filedata);
    if(r != TRUE) {
        return r;
    }
    *lpFindFileData = filedata_wtoa(filedata);
    return r;
}
auto WINAPI mFindClose(HANDLE hFindFile) -> BOOL {
    find_files.erase(hFindFile);
    return FindClose(hFindFile);
}
} // namespace
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
            hook::Symbol{"Kernel32.dll", "FindFirstFileExA", &rw::mFindNextFileA},
            hook::Symbol{"Kernel32.dll", "FindFirstFileExW", &rw::mFindFirstFileExW},
            hook::Symbol{"Kernel32.dll", "FindNextFileA", &rw::mFindNextFileA},
            hook::Symbol{"Kernel32.dll", "FindNextFileW", &rw::mFindNextFileW},
            hook::Symbol{"Kernel32.dll", "FindClose", &rw::mFindClose},
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
