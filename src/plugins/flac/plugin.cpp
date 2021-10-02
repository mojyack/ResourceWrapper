#include <array>
#include <filesystem>
#include <string_view>

#include "../../plugin.hpp"
#include "convert.hpp"

namespace rw {
class Flac : public Plugin {
  private:
    enum class TargetType {
        WAV,
    };
    struct Target {
        TargetType     type;
        const wchar_t* ext;
        bool (*convert)(const char*, HANDLE);
    };
    auto search_target(const wchar_t* path) const -> const Target* {
        const static auto TARGETS = std::array{
            Target{TargetType::WAV, L".wav", &plugin::flac::flac_to_wav},
        };
        const auto p = std::wstring_view(path);
        for(const auto& t : TARGETS) {
            if(p.ends_with(t.ext)) {
                auto target_path = std::filesystem::path(path);
                target_path.replace_extension(L".flac");
                if(std::filesystem::exists(target_path)) {
                    return &t;
                }
            }
        }
        return nullptr;
    }

  public:
    auto prepare_path(const wchar_t* path) -> std::optional<std::wstring> override {
        const auto target = search_target(path);
        if(target == nullptr) {
            return std::nullopt;
        }

        auto fake_path = std::filesystem::path(path).replace_extension(L".wav");
        return fake_path.wstring();
    }
    auto get_file_attributes(const wchar_t* const path) -> DWORD override {
        const auto target = search_target(path);
        if(target == nullptr) {
            return -1;
        }
        auto flac_path = std::filesystem::path(path).replace_extension(L".flac");
        return GetFileAttributesW(flac_path.wstring().data());
    }
    auto create_file(const wchar_t* const target_path, const wchar_t* const temp_path) -> HANDLE override {
        const auto target = search_target(target_path);
        if(target == nullptr) {
            return INVALID_HANDLE_VALUE;
        }

        auto       flac_path   = std::filesystem::path(target_path).replace_extension(L".flac");
        auto       r           = INVALID_HANDLE_VALUE;
        const auto temp_handle = get_tempfile(temp_path);
        if(temp_handle == INVALID_HANDLE_VALUE) {
            goto end;
        }
        if(!target->convert(flac_path.string().data(), temp_handle)) {
            goto end;
        }
        r = temp_handle;

    end:
        if(r != temp_handle) {
            CloseHandle(temp_handle);
        }
        return r;
    }
    Flac() {
        register_plugin(this);
    }
};
static auto flac = Flac();
} // namespace rw
