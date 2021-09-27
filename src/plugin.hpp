#pragma once
#include <optional>
#include <string>

#include <Windows.h>

namespace rw {
class Plugin {
  public:
    virtual auto prepare_path(const wchar_t* const path) -> std::optional<std::wstring> {
        return std::nullopt;
    }
    virtual auto get_file_attributes(const wchar_t* const path) -> DWORD {
        return -1;
    }
    virtual auto create_file(const wchar_t* const target_path, const wchar_t* const temp_path) -> HANDLE {
        return INVALID_HANDLE_VALUE;
    }
    virtual ~Plugin() {}
};

auto register_plugin(Plugin* plugin) -> void;
auto get_tempfile(const wchar_t* path) -> HANDLE;
}