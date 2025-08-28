#pragma once
#include <string>
#include <unordered_map>
#include <memory>
#include <chrono>
#include <asio.hpp>
#include "config.h"

using asio::ip::tcp;

struct WAFRequest {
    std::string method;
    std::string uri;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
    std::string remote_addr;
    std::string server_addr;
    int server_port;
};

struct WAFResponse {
    bool allowed = true;
    int status_code = 0;
    std::string message;
    std::string rule_id;
    int severity = 0;
};

class WAFClient {
public:
    explicit WAFClient(const Config& config);
    ~WAFClient();
    
    WAFResponse evaluate_request(const WAFRequest& request);
    bool is_waf_enabled() const { return config_.waf_enabled; }
    bool is_healthy() const;
    
private:
    std::string create_json_request(const WAFRequest& request);
    WAFResponse parse_json_response(const std::string& response);
    std::string make_http_request(const std::string& json_payload);
    
    const Config& config_;
    asio::io_context io_context_;
    std::chrono::steady_clock::time_point last_health_check_;
    bool last_health_status_;
    
    // Connection pooling could be added here in the future
    static constexpr int HEALTH_CHECK_INTERVAL_SECONDS = 30;
};