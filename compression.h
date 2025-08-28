#pragma once
#include <string>
#include <zlib.h>
#include <brotli/encode.h>
#include <zstd.h>

class CompressionHandler {
public:
    CompressionHandler();
    ~CompressionHandler();
    
    std::string compress(const std::string& data, const std::string& encoding);
    
private:
    std::string compress_gzip(const std::string& data);
    std::string compress_deflate(const std::string& data);
    std::string compress_brotli(const std::string& data);
    std::string compress_zstd(const std::string& data);
    
    // Compression contexts for reuse
    z_stream gzip_stream_;
    z_stream deflate_stream_;
    BrotliEncoderState* brotli_state_;
    ZSTD_CCtx* zstd_context_;
    
    bool gzip_initialized_;
    bool deflate_initialized_;
};