#include <filesystem>
#include <optional>
#include <vector>

#include <png.h>
#include <webp/decode.h>

#include "convert.hpp"

namespace {
auto read_file(const HANDLE file) -> std::optional<std::vector<uint8_t>> {
    auto r    = std::vector<uint8_t>();
    auto size = LARGE_INTEGER();
    if(GetFileSizeEx(file, &size) == 0) {
        return std::nullopt;
    }
    r.resize(size.QuadPart);
    auto       read        = DWORD();
    const auto read_result = ReadFile(file, r.data(), r.size(), &read, NULL);
    if(read_result != TRUE || read != r.size()) {
        return std::nullopt;
    }
    return r;
}
struct WebP {
    int      width;
    int      height;
    bool     has_alpha;
    uint8_t* data;
};
auto decode_webp(const HANDLE handle) -> std::optional<WebP> {
    const auto buf = read_file(handle);
    if(!buf.has_value()) {
        return std::nullopt;
    }
    auto features = WebPBitstreamFeatures();
    if(WebPGetFeatures(buf->data(), buf->size(), &features) != VP8_STATUS_OK) {
        return std::nullopt;
    }
    auto       width = int(), height = int();
    const auto data = features.has_alpha ? WebPDecodeRGBA(buf->data(), buf->size(), &width, &height) : WebPDecodeRGB(buf->data(), buf->size(), &width, &height);
    if(data == NULL) {
        return std::nullopt;
    }
    return WebP{width, height, features.has_alpha != 0, data};
}
auto write_callback(const png_structp png, const png_bytep data, const png_size_t length) -> void {
    const auto handle  = *static_cast<HANDLE*>(png_get_io_ptr(png));
    auto       written = DWORD();
    WriteFile(handle, data, length, &written, NULL);
}
} // namespace

namespace rw::plugin::webp {
auto webp_to_png(const HANDLE webp_handle, const HANDLE png_handle) -> bool {
    if(SetFilePointer(webp_handle, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        return false;
    }
    if(SetFilePointer(png_handle, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        return false;
    }
    const auto webp = decode_webp(webp_handle);
    if(!webp.has_value()) {
        return false;
    }

    static_assert(sizeof(png_byte) == sizeof(uint8_t), "png_byte is not 8-bit");
    const auto color_type = webp->has_alpha ? PNG_COLOR_TYPE_RGBA : PNG_COLOR_TYPE_RGB;
    const auto row_size   = sizeof(png_byte) * webp->width * (webp->has_alpha ? 4 : 3);

    auto r    = false;
    auto rows = png_bytepp(NULL);

    auto png  = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    auto info = png_create_info_struct(png);
    if(png == NULL || info == NULL) {
        goto end;
    }
    if(setjmp(png_jmpbuf(png))) {
        goto end;
    }
    png_set_write_fn(png, const_cast<HANDLE*>(&png_handle), write_callback, NULL);
    png_set_IHDR(png, info, webp->width, webp->height, 8, color_type, PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
    rows = reinterpret_cast<png_bytepp>(png_malloc(png, sizeof(png_bytep) * webp->height));
    if(rows == NULL) {
        goto end;
    }
    png_set_rows(png, info, rows);
    for(auto r = decltype(webp->height)(0); r < webp->height; r += 1) {
        rows[r] = webp->data + r * row_size;
    }
    png_write_png(png, info, PNG_TRANSFORM_IDENTITY, NULL);
    if(SetFilePointer(png_handle, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        goto end;
    }
    r = true;

end:
    if(rows != NULL) {
        png_free(png, rows);
    }
    if(png != NULL) {
        png_destroy_write_struct(&png, &info);
    }
    if(webp.has_value()) {
        WebPFree(webp->data);
    }
    return r;
}
auto webp_to_bmp(const HANDLE webp_handle, const HANDLE bmp_handle) -> bool {
    if(SetFilePointer(webp_handle, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        return false;
    }
    if(SetFilePointer(bmp_handle, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        return false;
    }
    const auto webp = decode_webp(webp_handle);
    if(!webp.has_value()) {
        return false;
    }

    const auto row_size = webp->width * (!webp->has_alpha ? 3 : 4);
    const auto bytes    = row_size * webp->height;

    auto info_header      = (void*)(nullptr);
    auto info_header_size = size_t(0);
    
    //if(config.v5_header) {
    //    info_header_size = sizeof(BITMAPV5HEADER);
    //    auto h           = new BITMAPV5HEADER;
    //    h->bV5RedMask    = 0;
    //    h->bV5GreenMask  = 0;
    //    h->bV5BlueMask   = 0;
    //    h->bV5AlphaMask  = 0;
    //    h->bV5CSType     = LCS_sRGB;
    //    h->bV5Intent     = LCS_GM_BUSINESS;
    //    h->bV5Reserved   = 0;
    //    info_header      = h;
    //} else {
    info_header_size = sizeof(BITMAPINFOHEADER);
    info_header      = new BITMAPINFOHEADER;
    //}

    *reinterpret_cast<BITMAPINFOHEADER*>(info_header) = BITMAPINFOHEADER{static_cast<DWORD>(info_header_size), webp->width, webp->height, 1, static_cast<uint16_t>(32), BI_RGB, 0, 0x1274, 0x1274, 0, 0};
   
    auto file_header = BITMAPFILEHEADER{('M' << 8) | 'B', static_cast<DWORD>(sizeof(BITMAPFILEHEADER) + info_header_size + bytes), 0, 0, static_cast<DWORD>(sizeof(BITMAPFILEHEADER) + info_header_size)};

    auto written = DWORD();
    WriteFile(bmp_handle, &file_header, sizeof(file_header), &written, NULL);
    WriteFile(bmp_handle, info_header, info_header_size, &written, NULL);

    auto buf = std::vector<uint8_t>();
    buf.reserve(webp->height * webp->width * 4);
    for(auto r = webp->height - 1; r >= 0; r -= 1) {
        const auto row = webp->data + r * row_size;
        for(auto c = size_t(0); c < webp->width; c += 1) {
            const auto p = row + c * (webp->has_alpha ? 4 : 3);
            buf.emplace_back(p[2]);
            buf.emplace_back(p[1]);
            buf.emplace_back(p[0]);
            buf.emplace_back(webp->has_alpha ? p[3] : 0xFF);
        }
    }
    WriteFile(bmp_handle, buf.data(), buf.size(), &written, NULL);

    delete info_header;
    WebPFree(webp->data);
    if(SetFilePointer(bmp_handle, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        return false;
    }
    return true;
}
} // namespace rw::plugin::webp
