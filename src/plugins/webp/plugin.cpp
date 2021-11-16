#include <array>
#include <filesystem>
#include <string_view>

#include "../../plugin.hpp"
#include "convert.hpp"

namespace {
inline auto close_valid_handle(const HANDLE handle) -> void {
    if(handle != INVALID_HANDLE_VALUE) {
        CloseHandle(handle);
    }
}
} // namespace

namespace rw {
enum class TargetType {
    PNG,
    BMP
};
struct Target {
    TargetType     type;
    const wchar_t* ext;
    bool (*convert)(HANDLE, HANDLE);
};
const static auto TARGETS = std::array{
    Target{TargetType::PNG, L".png", &plugin::webp::webp_to_png},
    Target{TargetType::BMP, L".bmp", &plugin::webp::webp_to_bmp},
};
class Webp : public Plugin {
  private:
    auto search_target(const wchar_t* path) const -> const Target* {
        const auto p = std::wstring_view(path);
        for(const auto& t : TARGETS) {
            if(p.ends_with(t.ext)) {
                auto target_path = std::filesystem::path(path);
                target_path.replace_extension(L".webp");
                if(std::filesystem::exists(target_path)) {
                    return &t;
                }
            }
        }
        return nullptr;
    }
    auto get_fake_path(const wchar_t* path) const -> const Target* {
        const auto p = std::wstring_view(path);
        if(!p.ends_with(L".webp")) {
            return nullptr;
        }
        return &TARGETS[0];
    }

  public:
    auto prepare_path(const wchar_t* path) -> std::optional<std::wstring> override {
        const auto target = get_fake_path(path);
        if(target == nullptr) {
            return std::nullopt;
        }

        auto fake_path = std::filesystem::path(path).replace_extension(target->ext);
        return fake_path.wstring();
    }
    auto get_file_attributes(const wchar_t* const path) -> DWORD override {
        const auto target = search_target(path);
        if(target == nullptr) {
            return -1;
        }
        auto flac_path = std::filesystem::path(path).replace_extension(L".webp");
        return GetFileAttributesW(flac_path.wstring().data());
    }

    auto create_file(const wchar_t* const target_path, const wchar_t* const temp_path) -> HANDLE override {
        auto target = search_target(target_path);
        if(target == nullptr) {
            return INVALID_HANDLE_VALUE;
        }

        auto       webp_path   = std::filesystem::path(target_path).replace_extension(L".webp");
        auto       r           = INVALID_HANDLE_VALUE;
        const auto webp_handle = CreateFileW(webp_path.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        const auto temp_handle = get_tempfile(temp_path);
        if(webp_handle == INVALID_HANDLE_VALUE || temp_handle == INVALID_HANDLE_VALUE) {
            goto end;
        }
        if(!target->convert(webp_handle, temp_handle)) {
            goto end;
        }
        r = temp_handle;

    end:
        close_valid_handle(webp_handle);
        if(r != temp_handle) {
            close_valid_handle(temp_handle);
        }
        return r;
    }
    Webp() {
        register_plugin(this);
    }
};
static auto webp = Webp();
} // namespace rw
