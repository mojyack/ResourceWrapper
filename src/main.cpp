#include <array>

#include <Windows.h>

#include "hook/error.hpp"
#include "hook/hook.hpp"

namespace {
auto execute(PROCESS_INFORMATION& info, const wchar_t* const path) {
    auto startup = STARTUPINFOW{0};
    return CreateProcessW(
               path,
               NULL,
               NULL,
               NULL,
               FALSE,
               CREATE_SUSPENDED,
               NULL,
               NULL,
               &startup,
               &info) != FALSE;
}
auto inject(const HANDLE process, const HINSTANCE handle) -> void {
    const auto self_path = hook::get_path_from_handle(handle);
    
    const auto size_bytes = (self_path.size() + 1) * sizeof(self_path[0]);
    const auto remote_mem = VirtualAllocEx(process, NULL, size_bytes, MEM_COMMIT, PAGE_READWRITE);
    ASSERT(remote_mem != NULL, "error at VirtualAllocEx()")

    auto written = SIZE_T(0);
    ASSERT(WriteProcessMemory(process, remote_mem, self_path.data(), size_bytes, &written) != FALSE, "error at WriteProcessMemory()")

    const auto loadlibrary_pointer = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");

    auto       thread_id     = DWORD(0);
    const auto thread_handle = CreateRemoteThread(process, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(loadlibrary_pointer), remote_mem, 0, &thread_id);
    ASSERT(thread_handle != NULL, "dll not found")

    WaitForSingleObject(thread_handle, INFINITE);
    auto exit_code = DWORD(0);
    GetExitCodeThread(thread_handle, &exit_code);

    CloseHandle(thread_handle);
    VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
}
} // namespace
extern "C" __declspec(dllexport) auto CALLBACK RunW([[maybe_unused]] const HWND hWnd, const HINSTANCE hInstance, const LPWSTR lpszCmdline, [[maybe_unused]] const int nCmdShow) -> void {
    auto info = PROCESS_INFORMATION{0};

    ASSERT(execute(info, lpszCmdline), "failed to launch target")


    auto self = HMODULE();
    ASSERT(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)(&RunW), &self) != 0, "failed to locate self handle")
    inject(info.hProcess, self);
    ResumeThread(info.hThread);

    CloseHandle(info.hThread);
    CloseHandle(info.hProcess);
}