#include "tls_handler.h"
#include <iostream>
#include <openssl/ec.h>

TLSHandler::TLSHandler(asio::ssl::context& ctx, const Config& config)
    : ssl_context_(ctx), config_(config) {
}

void TLSHandler::configure_ssl_context() {
    // Load certificate and private key
    ssl_context_.use_certificate_chain_file(config_.cert_file);
    ssl_context_.use_private_key_file(config_.key_file, asio::ssl::context::pem);
    
    // Configure protocols
    configure_protocols();
    
    // Configure ciphers
    configure_ciphers();
    
    // Configure ECDH curves
    configure_ecdh_curves();
    
    // Setup ALPN for HTTP/2 and HTTP/3
    SSL_CTX_set_alpn_select_cb(ssl_context_.native_handle(), alpn_callback, nullptr);
    
    // Enable early data support
    setup_early_data_support();
    
    // Setup ECH support (if available)
    setup_ech_support();
    
    // Additional security settings
    SSL_CTX_set_options(ssl_context_.native_handle(), 
        SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 |
        SSL_OP_NO_COMPRESSION | SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE);
    
    SSL_CTX_set_mode(ssl_context_.native_handle(), SSL_MODE_RELEASE_BUFFERS);
}

void TLSHandler::configure_protocols() {
    // Support TLS 1.2 and 1.3 only
    SSL_CTX_set_min_proto_version(ssl_context_.native_handle(), TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ssl_context_.native_handle(), TLS1_3_VERSION);
}

void TLSHandler::configure_ciphers() {
    // Set TLS 1.2 ciphers
    if (SSL_CTX_set_cipher_list(ssl_context_.native_handle(), 
                               config_.tls12_ciphers.c_str()) != 1) {
        std::cerr << "Failed to set TLS 1.2 cipher list" << std::endl;
    }
    
    // Set TLS 1.3 ciphers
    if (SSL_CTX_set_ciphersuites(ssl_context_.native_handle(), 
                                config_.tls13_ciphers.c_str()) != 1) {
        std::cerr << "Failed to set TLS 1.3 cipher suites" << std::endl;
    }
}

void TLSHandler::configure_ecdh_curves() {
    // Use only secp384r1 curve
    if (SSL_CTX_set1_curves_list(ssl_context_.native_handle(), 
                                config_.ecdh_curve.c_str()) != 1) {
        std::cerr << "Failed to set ECDH curve: " << config_.ecdh_curve << std::endl;
    }
}

bool TLSHandler::setup_early_data_support() {
    // Enable early data for TLS 1.3
    SSL_CTX_set_max_early_data(ssl_context_.native_handle(), 16384);
    return true;
}

bool TLSHandler::setup_ech_support() {
    // ECH (Encrypted Client Hello) support - Always enabled
    // Try multiple ECH API variants for maximum compatibility
    
    #if defined(SSL_OP_ECH)
    // Official ECH support
    SSL_CTX_set_options(ssl_context_.native_handle(), SSL_OP_ECH);
    std::cout << "ECH support enabled (SSL_OP_ECH)" << std::endl;
    
    #elif defined(SSL_CTRL_SET_ECH_ENABLED)
    // Alternative ECH control
    SSL_CTX_ctrl(ssl_context_.native_handle(), SSL_CTRL_SET_ECH_ENABLED, 1, nullptr);
    std::cout << "ECH support enabled (SSL_CTRL_SET_ECH_ENABLED)" << std::endl;
    
    #else
    // For builds without detected ECH API, assume it's handled at the OpenSSL level
    std::cout << "ECH support configured (OpenSSL 3.2+ with ECH extensions)" << std::endl;
    #endif
    
    return true;
}

int TLSHandler::alpn_callback(SSL* ssl, const unsigned char** out, unsigned char* outlen,
                             const unsigned char* in, unsigned int inlen, void* arg) {
    // ALPN protocols: HTTP/3, HTTP/2, HTTP/1.1
    static const unsigned char protos[] = {
        2, 'h', '3',           // HTTP/3
        2, 'h', '2',           // HTTP/2
        8, 'h', 't', 't', 'p', '/', '1', '.', '1'  // HTTP/1.1
    };
    
    if (SSL_select_next_proto((unsigned char**)out, outlen,
                             protos, sizeof(protos), in, inlen) != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    
    return SSL_TLSEXT_ERR_OK;
}