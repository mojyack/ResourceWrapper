#include <string>
#include <vector>

#include "plugin.hpp"

namespace rw {
auto plugins = std::vector<Plugin*>();

auto register_plugin(Plugin* const plugin) -> void {
    plugins.emplace_back(plugin);
}
auto get_tempfile(const wchar_t* path) -> HANDLE {
    constexpr auto FLAGS = FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
    return CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FLAGS, NULL);
}
} // namespace rw
