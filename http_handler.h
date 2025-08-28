#pragma once
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <asio.hpp>
#include <asio/ssl.hpp>
#include "config.h"
#include "compression.h"
#include "waf_client.h"

using asio::ip::tcp;

class HTTPHandler {
public:
    explicit HTTPHandler(const Config& config);
    
    void handle_http_connection(std::shared_ptr<tcp::socket> socket);
    void handle_https_connection(std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_socket);

private:
    struct HTTPRequest {
        std::string method;
        std::string path;
        std::string version;
        std::unordered_map<std::string, std::string> headers;
        std::string body;
        bool is_websocket_upgrade = false;
    };
    
    struct HTTPResponse {
        int status_code = 200;
        std::string status_text = "OK";
        std::unordered_map<std::string, std::string> headers;
        std::string body;
    };
    
    HTTPRequest parse_request(const std::string& raw_request);
    HTTPResponse create_health_check_response();
    HTTPResponse create_redirect_response(const std::string& host, const std::string& path);
    
    void process_request(std::shared_ptr<tcp::socket> socket, const HTTPRequest& request, const std::string& client_ip);
    void process_ssl_request(std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_socket, const HTTPRequest& request, const std::string& client_ip);
    
    std::string calculate_xff_headers(const std::string& client_ip, const HTTPRequest& request);
    bool should_compress(const std::string& content_type);
    std::string get_supported_encoding(const std::string& accept_encoding);
    
    void forward_to_backend(const HTTPRequest& request, HTTPResponse& response, const std::string& xff_headers);
    void handle_websocket_upgrade(std::shared_ptr<tcp::socket> client_socket, const HTTPRequest& request, const std::string& xff_headers);
    
    bool evaluate_waf_request(const HTTPRequest& request, const std::string& client_ip, HTTPResponse& waf_rejection_response);
    std::string serialize_response(const HTTPResponse& response);
    
    const Config& config_;
    std::unique_ptr<CompressionHandler> compression_handler_;
    std::unique_ptr<WAFClient> waf_client_;
    asio::io_context backend_io_context_;
    
    // Supported content types for compression
    const std::vector<std::string> compressible_types_ = {
        "text/plain", "text/css", "text/xml", "application/xml",
        "application/json", "application/javascript", "text/javascript",
        "application/manifest+json", "application/rss+xml", "image/svg+xml"
    };
};