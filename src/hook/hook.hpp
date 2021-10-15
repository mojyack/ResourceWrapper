#pragma once
#include <string>

#include "pe.hpp"

namespace hook {
auto inject(const HANDLE process) -> void;

struct Symbol {
    const char* file;
    const char* func;
    const void* inject;
    const char* slave    = nullptr;
    const void* original = nullptr;
};
auto init(const Symbol symbols[], size_t size) -> void;
auto hook_imports(PEFile pe, bool hook, bool is_self = false) -> bool;
auto hook_all_imports(HMODULE self, bool hook) -> bool;
auto hook_exports(const char* file, const char* func, const void* inject) -> void*;
auto hook_all_exports() -> void;

/* convinient */
auto get_path_from_handle(HINSTANCE handle) -> std::wstring;
} // namespace hook
