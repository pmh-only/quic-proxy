#pragma once
#include <asio/ssl.hpp>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "config.h"

class TLSHandler {
public:
    explicit TLSHandler(asio::ssl::context& ctx, const Config& config);
    void configure_ssl_context();
    bool setup_ech_support();
    bool setup_early_data_support();

private:
    void configure_ciphers();
    void configure_ecdh_curves();
    void configure_protocols();
    static int alpn_callback(SSL* ssl, const unsigned char** out, unsigned char* outlen,
                           const unsigned char* in, unsigned int inlen, void* arg);
    
    asio::ssl::context& ssl_context_;
    const Config& config_;
};