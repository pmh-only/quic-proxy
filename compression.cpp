#include "compression.h"
#include <vector>
#include <cstring>

CompressionHandler::CompressionHandler() 
    : gzip_initialized_(false), deflate_initialized_(false) {
    
    // Initialize compression contexts
    std::memset(&gzip_stream_, 0, sizeof(gzip_stream_));
    std::memset(&deflate_stream_, 0, sizeof(deflate_stream_));
    
    brotli_state_ = BrotliEncoderCreateInstance(nullptr, nullptr, nullptr);
    zstd_context_ = ZSTD_createCCtx();
}

CompressionHandler::~CompressionHandler() {
    if (gzip_initialized_) {
        deflateEnd(&gzip_stream_);
    }
    if (deflate_initialized_) {
        deflateEnd(&deflate_stream_);
    }
    if (brotli_state_) {
        BrotliEncoderDestroyInstance(brotli_state_);
    }
    if (zstd_context_) {
        ZSTD_freeCCtx(zstd_context_);
    }
}

std::string CompressionHandler::compress(const std::string& data, const std::string& encoding) {
    if (encoding == "gzip") {
        return compress_gzip(data);
    } else if (encoding == "deflate") {
        return compress_deflate(data);
    } else if (encoding == "br") {
        return compress_brotli(data);
    } else if (encoding == "zstd") {
        return compress_zstd(data);
    }
    return "";
}

std::string CompressionHandler::compress_gzip(const std::string& data) {
    if (!gzip_initialized_) {
        if (deflateInit2(&gzip_stream_, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 
                        15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
            return "";
        }
        gzip_initialized_ = true;
    }
    
    deflateReset(&gzip_stream_);
    
    std::vector<char> buffer(data.size() + (data.size() / 1000) + 12);
    
    gzip_stream_.avail_in = data.size();
    gzip_stream_.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data.data()));
    gzip_stream_.avail_out = buffer.size();
    gzip_stream_.next_out = reinterpret_cast<Bytef*>(buffer.data());
    
    if (deflate(&gzip_stream_, Z_FINISH) != Z_STREAM_END) {
        return "";
    }
    
    size_t compressed_size = buffer.size() - gzip_stream_.avail_out;
    return std::string(buffer.data(), compressed_size);
}

std::string CompressionHandler::compress_deflate(const std::string& data) {
    if (!deflate_initialized_) {
        if (deflateInit(&deflate_stream_, Z_DEFAULT_COMPRESSION) != Z_OK) {
            return "";
        }
        deflate_initialized_ = true;
    }
    
    deflateReset(&deflate_stream_);
    
    std::vector<char> buffer(data.size() + (data.size() / 1000) + 12);
    
    deflate_stream_.avail_in = data.size();
    deflate_stream_.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data.data()));
    deflate_stream_.avail_out = buffer.size();
    deflate_stream_.next_out = reinterpret_cast<Bytef*>(buffer.data());
    
    if (deflate(&deflate_stream_, Z_FINISH) != Z_STREAM_END) {
        return "";
    }
    
    size_t compressed_size = buffer.size() - deflate_stream_.avail_out;
    return std::string(buffer.data(), compressed_size);
}

std::string CompressionHandler::compress_brotli(const std::string& data) {
    if (!brotli_state_) {
        return "";
    }
    
    size_t max_output = BrotliEncoderMaxCompressedSize(data.size());
    std::vector<uint8_t> buffer(max_output);
    
    size_t output_size = max_output;
    if (!BrotliEncoderCompress(BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_WINDOW,
                              BROTLI_DEFAULT_MODE, data.size(),
                              reinterpret_cast<const uint8_t*>(data.data()),
                              &output_size, buffer.data())) {
        return "";
    }
    
    return std::string(reinterpret_cast<char*>(buffer.data()), output_size);
}

std::string CompressionHandler::compress_zstd(const std::string& data) {
    if (!zstd_context_) {
        return "";
    }
    
    size_t max_output = ZSTD_compressBound(data.size());
    std::vector<char> buffer(max_output);
    
    size_t compressed_size = ZSTD_compressCCtx(zstd_context_, buffer.data(), max_output,
                                              data.data(), data.size(), 1);
    
    if (ZSTD_isError(compressed_size)) {
        return "";
    }
    
    return std::string(buffer.data(), compressed_size);
}