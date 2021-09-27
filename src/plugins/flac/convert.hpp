#pragma once
#include <Windows.h>

namespace rw::plugin::flac {
auto flac_to_wav(const char* flac_path, const HANDLE wav_handle) -> bool;
}
