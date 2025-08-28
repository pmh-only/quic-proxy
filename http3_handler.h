#pragma once
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <array>
#include <asio.hpp>
#include <openssl/ssl.h>
#ifdef ENABLE_ADVANCED_FEATURES
// HTTP/3 support available through nghttp3
// QUIC transport handled through nghttp3 library
#endif
#include <nghttp3/nghttp3.h>
#include "config.h"

using asio::ip::udp;

class HTTP3Handler {
public:
    explicit HTTP3Handler(const Config& config, asio::io_context& io_context);
    ~HTTP3Handler();
    
    void start_quic_server();
    void stop();
    bool is_http3_supported() const;

private:
    struct QuicConnection {
        SSL* ssl;
        nghttp3_conn* h3_conn;
        udp::endpoint endpoint;
        std::string connection_id;
        std::unordered_map<int64_t, std::string> stream_buffers;
        bool early_data_enabled;
        bool connection_established;
        
        QuicConnection(SSL* s, const udp::endpoint& ep, const std::string& conn_id)
            : ssl(s), h3_conn(nullptr), endpoint(ep), connection_id(conn_id),
              early_data_enabled(false), connection_established(false) {}
        
        ~QuicConnection() {
            if (h3_conn) {
                nghttp3_conn_del(h3_conn);
            }
            if (ssl) {
                SSL_free(ssl);
            }
        }
    };
    
    struct HTTP3Request {
        std::string method;
        std::string path;
        std::string scheme;
        std::string authority;
        std::unordered_map<std::string, std::string> headers;
        std::string body;
        bool early_data;
    };
    
    struct HTTP3Response {
        int status_code = 200;
        std::unordered_map<std::string, std::string> headers;
        std::string body;
    };
    
    // QUIC connection management
    std::shared_ptr<QuicConnection> create_quic_connection(const udp::endpoint& endpoint);
    void process_quic_data(std::shared_ptr<QuicConnection> conn, const uint8_t* data, size_t len);
    void send_quic_data(std::shared_ptr<QuicConnection> conn, const uint8_t* data, size_t len);
    
    // HTTP/3 callbacks
    static int on_begin_headers(nghttp3_conn* conn, int64_t stream_id, void* user_data,
                               void* stream_user_data);
    static int on_recv_header(nghttp3_conn* conn, int64_t stream_id,
                             int32_t token, nghttp3_rcbuf* name, nghttp3_rcbuf* value,
                             uint8_t flags, void* user_data, void* stream_user_data);
    static int on_end_headers(nghttp3_conn* conn, int64_t stream_id,
                             int fin, void* user_data, void* stream_user_data);
    static int on_recv_data(nghttp3_conn* conn, int64_t stream_id,
                           const uint8_t* data, size_t datalen,
                           void* user_data, void* stream_user_data);
    static int on_end_stream(nghttp3_conn* conn, int64_t stream_id,
                            void* user_data, void* stream_user_data);
    
    // Request processing
    void process_http3_request(std::shared_ptr<QuicConnection> conn, int64_t stream_id);
    void forward_to_backend(const HTTP3Request& request, HTTP3Response& response, 
                           const std::string& client_ip);
    void send_http3_response(std::shared_ptr<QuicConnection> conn, int64_t stream_id,
                            const HTTP3Response& response);
    HTTP3Request parse_http3_request(std::shared_ptr<QuicConnection> conn, int64_t stream_id);
    HTTP3Response parse_backend_response(const std::string& raw_response);
    std::string read_full_backend_response(asio::ip::tcp::socket& backend_socket);
    
    // 0-RTT support
    void enable_0rtt_support(std::shared_ptr<QuicConnection> conn);
    bool process_early_data(std::shared_ptr<QuicConnection> conn, const uint8_t* data, size_t len);
    
    // Utility functions
    std::string calculate_xff_headers(const std::string& client_ip, const HTTP3Request& request);
    bool should_compress(const std::string& content_type);
    std::string get_supported_encoding(const std::string& accept_encoding);
    std::string generate_connection_id();
    
    const Config& config_;
    std::unique_ptr<class CompressionHandler> compression_handler_;
    std::unique_ptr<class WAFClient> waf_client_;
    
    // QUIC context
    SSL_CTX* quic_ctx_;
    std::unique_ptr<udp::socket> udp_socket_;
    asio::io_context& io_context_;
    void start_receive();
    void handle_quic_packet(const std::array<char, 4096>& buffer, size_t length,
                           const udp::endpoint& endpoint);
    
    // Connection management
    std::unordered_map<std::string, std::shared_ptr<QuicConnection>> connections_;
    std::unordered_map<int64_t, HTTP3Request> stream_requests_;
    
    // Backend I/O context
    asio::io_context backend_io_context_;
    
    // Receive buffer
    std::array<char, 4096> recv_buffer_;
    udp::endpoint remote_endpoint_;
    
    // Supported content types for compression
    const std::vector<std::string> compressible_types_ = {
        "text/plain", "text/css", "text/xml", "application/xml",
        "application/json", "application/javascript", "text/javascript",
        "application/manifest+json", "application/rss+xml", "image/svg+xml"
    };
};