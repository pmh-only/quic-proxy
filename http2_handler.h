#pragma once
#include <memory>
#include <string>
#include <unordered_map>
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <nghttp2/nghttp2.h>
#include "config.h"

using asio::ip::tcp;

class HTTP2Handler {
public:
    explicit HTTP2Handler(const Config& config);
    ~HTTP2Handler();
    
    void handle_http2_connection(std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_socket);

private:
    struct HTTP2Session {
        std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_socket;
        nghttp2_session* session;
        std::string read_buffer;
        std::string write_buffer;
        bool session_terminated;
        bool write_pending;
        HTTP2Handler* handler_ptr;
        
        // Response body storage for active streams
        std::unordered_map<int32_t, std::string> response_bodies;
        
        HTTP2Session(std::shared_ptr<asio::ssl::stream<tcp::socket>> socket, HTTP2Handler* handler) 
            : ssl_socket(socket), session(nullptr), session_terminated(false), write_pending(false), handler_ptr(handler) {}
        
        ~HTTP2Session() {
            if (session) {
                nghttp2_session_del(session);
            }
        }
    };
    
    // nghttp2 callbacks
    static ssize_t send_callback(nghttp2_session* session, const uint8_t* data,
                                size_t length, int flags, void* user_data);
    static int on_frame_recv_callback(nghttp2_session* session,
                                     const nghttp2_frame* frame, void* user_data);
    static int on_data_chunk_recv_callback(nghttp2_session* session, uint8_t flags,
                                          int32_t stream_id, const uint8_t* data,
                                          size_t len, void* user_data);
    static int on_stream_close_callback(nghttp2_session* session, int32_t stream_id,
                                       uint32_t error_code, void* user_data);
    static int on_header_callback(nghttp2_session* session, const nghttp2_frame* frame,
                                 const uint8_t* name, size_t namelen,
                                 const uint8_t* value, size_t valuelen,
                                 uint8_t flags, void* user_data);
    static int on_begin_headers_callback(nghttp2_session* session,
                                        const nghttp2_frame* frame, void* user_data);
    
    // Session management
    void start_session(std::shared_ptr<HTTP2Session> session);
    void read_data(std::shared_ptr<HTTP2Session> session);
    void write_data(std::shared_ptr<HTTP2Session> session);
    void process_request(std::shared_ptr<HTTP2Session> session, int32_t stream_id);
    std::shared_ptr<HTTP2Session> find_session_by_ptr(HTTP2Session* raw_ptr);
    
    // Request processing
    struct HTTP2Request {
        std::string method;
        std::string path;
        std::string scheme;
        std::string authority;
        std::unordered_map<std::string, std::string> headers;
        std::string body;
    };
    
    struct HTTP2Response {
        int status_code = 200;
        std::unordered_map<std::string, std::string> headers;
        std::string body;
    };
    
    HTTP2Request parse_request(std::shared_ptr<HTTP2Session> session, int32_t stream_id);
    void forward_to_backend(const HTTP2Request& request, HTTP2Response& response, const std::string& client_ip);
    void send_response(std::shared_ptr<HTTP2Session> session, int32_t stream_id, const HTTP2Response& response);
    
    // Utility functions
    std::string calculate_xff_headers(const std::string& client_ip, const HTTP2Request& request);
    bool should_compress(const std::string& content_type);
    std::string get_supported_encoding(const std::string& accept_encoding);
    HTTP2Response parse_backend_response(const std::string& raw_response);
    std::string read_full_backend_response(tcp::socket& backend_socket);
    
    const Config& config_;
    std::unique_ptr<class CompressionHandler> compression_handler_;
    std::unique_ptr<class WAFClient> waf_client_;
    asio::io_context backend_io_context_;
    
    // Stream data storage (per session)
    std::unordered_map<HTTP2Session*, std::unordered_map<int32_t, HTTP2Request>> session_stream_requests_;
    
    // Session tracking
    std::unordered_map<HTTP2Session*, std::shared_ptr<HTTP2Session>> active_sessions_;
    
    // Supported content types for compression
    const std::vector<std::string> compressible_types_ = {
        "text/plain", "text/css", "text/xml", "application/xml",
        "application/json", "application/javascript", "text/javascript",
        "application/manifest+json", "application/rss+xml", "image/svg+xml"
    };
};