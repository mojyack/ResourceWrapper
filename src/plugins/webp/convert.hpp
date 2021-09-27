#pragma once
#include <Windows.h>

namespace rw::plugin::webp {
auto webp_to_png(const HANDLE webp_handle, const HANDLE png_handle) -> bool;
auto webp_to_bmp(const HANDLE webp_handle, const HANDLE bmp_handle) -> bool;
}
