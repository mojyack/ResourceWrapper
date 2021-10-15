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
} // namespace
extern "C" __declspec(dllexport) auto CALLBACK RunW([[maybe_unused]] const HWND hWnd, const HINSTANCE hInstance, const LPWSTR lpszCmdline, [[maybe_unused]] const int nCmdShow) -> void {
    auto info = PROCESS_INFORMATION{0};

    ASSERT(execute(info, lpszCmdline), "failed to launch target")
    
    hook::inject(info.hProcess);
    ResumeThread(info.hThread);

    CloseHandle(info.hThread);
    CloseHandle(info.hProcess);
}
