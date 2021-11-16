#include <vector>

#include <FLAC++/decoder.h>

#include "convert.hpp"

namespace rw::plugin::flac {
class Decoder : public FLAC::Decoder::File {
  private:
    std::vector<uint8_t> decoded;
    FLAC__uint64         total_samples = 0;
    uint32_t             sample_rate   = 0;
    uint32_t             channels      = 0;
    uint32_t             bps           = 0;

    auto append_buffer(const void* const data, const size_t size) -> void {
        const auto d = reinterpret_cast<const uint8_t*>(data);
        decoded.insert(decoded.end(), d, d + size);
    }
    auto append_buffer(auto data) -> void {
        append_buffer(&data, sizeof(data));
    }
    auto write_callback(const FLAC__Frame* const frame, const FLAC__int32* const buffer[]) -> FLAC__StreamDecoderWriteStatus override {
        const auto total_size = static_cast<FLAC__uint32>(total_samples * channels * (bps / 8));
        if(total_samples == 0) {
            return FLAC__STREAM_DECODER_WRITE_STATUS_ABORT;
        }
        if(frame->header.number.sample_number == 0) {
            append_buffer("RIFF", 4);
            append_buffer(uint32_t(total_size + 36));
            append_buffer("WAVEfmt ", 8);
            append_buffer(uint32_t(16));  // fmt chunk size
            append_buffer(uint16_t(1));   // format = PCM
            append_buffer(uint16_t(channels));
            append_buffer(uint32_t(sample_rate));
            append_buffer(uint32_t(sample_rate * channels * (bps / 8))); // bytes-per-sec
            append_buffer(uint16_t(channels * (bps / 8)));               // block align
            append_buffer(uint16_t(bps));
            append_buffer("data", 4);
            append_buffer(uint32_t(total_size));
        }
        const auto bytes = frame->header.blocksize * channels * (bps / 8);
        decoded.reserve(decoded.size() + bytes);
        for(auto i = uint32_t(0); i < frame->header.blocksize; i += 1) {
            for(auto c = uint32_t(0); c < channels; c += 1) {
                const auto* block = reinterpret_cast<const uint8_t*>(&buffer[c][i]);
                append_buffer(block, bps / 8);
            }
        }
        return FLAC__STREAM_DECODER_WRITE_STATUS_CONTINUE;
    }
    auto metadata_callback(const FLAC__StreamMetadata* const metadata) -> void override {
        switch(metadata->type) {
        case FLAC__METADATA_TYPE_STREAMINFO:
            total_samples = metadata->data.stream_info.total_samples;
            sample_rate   = metadata->data.stream_info.sample_rate;
            channels      = metadata->data.stream_info.channels;
            bps           = metadata->data.stream_info.bits_per_sample;
            break;
        default:
            break;
        }
    }
    auto error_callback(const FLAC__StreamDecoderErrorStatus status) -> void override {}

  public:
    auto get_decoded() const -> const std::vector<uint8_t>& {
        return decoded;
    }
    Decoder() {}
};

auto flac_to_wav(const char* const flac_path, const HANDLE wav_handle) -> bool {
    auto decoder = Decoder();
    if(decoder.init(flac_path) != FLAC__STREAM_DECODER_INIT_STATUS_OK) {
        return false;
    }
    const auto r = decoder.process_until_end_of_stream();
    const auto& decoded = decoder.get_decoded();
    WriteFile(wav_handle, decoded.data(), decoded.size(), NULL, NULL);
    if(SetFilePointer(wav_handle, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        return false;
    }
    return r;
}
} // namespace rw::plugin::flac
