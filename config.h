#pragma once
#include <string>
#include <cstdlib>

class Config {
public:
    std::string backend_host = "127.0.0.1";
    int backend_port = 8080;
    std::string cert_file = "/etc/ssl/certs/server.crt";
    std::string key_file = "/etc/ssl/private/server.key";
    int http_port = 80;
    int https_port = 443;
    
    // TLS Configuration
    std::string tls12_ciphers = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";
    std::string tls13_ciphers = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";
    std::string ecdh_curve = "secp384r1";
    
    // WAF Configuration
    bool waf_enabled = true;
    std::string waf_host = "127.0.0.1";
    int waf_port = 9000;
    int waf_timeout_ms = 1000;
    
    void load_from_env() {
        const char* backend = std::getenv("BACKEND_HOST");
        if (backend) {
            backend_host = backend;
        }
        
        const char* port = std::getenv("BACKEND_PORT");
        if (port) {
            backend_port = std::atoi(port);
        }
        
        const char* cert = std::getenv("TLS_CERT_FILE");
        if (cert) {
            cert_file = cert;
        }
        
        const char* key = std::getenv("TLS_KEY_FILE");
        if (key) {
            key_file = key;
        }
        
        const char* http_p = std::getenv("HTTP_PORT");
        if (http_p) {
            http_port = std::atoi(http_p);
        }
        
        const char* https_p = std::getenv("HTTPS_PORT");
        if (https_p) {
            https_port = std::atoi(https_p);
        }
        
        // WAF configuration from environment
        const char* waf_enabled_env = std::getenv("WAF_ENABLED");
        if (waf_enabled_env) {
            waf_enabled = (std::string(waf_enabled_env) == "true" || std::string(waf_enabled_env) == "1");
        }
        
        const char* waf_host_env = std::getenv("WAF_HOST");
        if (waf_host_env) {
            waf_host = waf_host_env;
        }
        
        const char* waf_port_env = std::getenv("WAF_PORT");
        if (waf_port_env) {
            waf_port = std::atoi(waf_port_env);
        }
        
        const char* waf_timeout_env = std::getenv("WAF_TIMEOUT_MS");
        if (waf_timeout_env) {
            waf_timeout_ms = std::atoi(waf_timeout_env);
        }
    }
};