#include "waf_client.h"
#include <sstream>
#include <iostream>
#include <regex>

WAFClient::WAFClient(const Config& config) 
    : config_(config), last_health_status_(false) {
    last_health_check_ = std::chrono::steady_clock::now() - std::chrono::seconds(HEALTH_CHECK_INTERVAL_SECONDS + 1);
}

WAFClient::~WAFClient() = default;

WAFResponse WAFClient::evaluate_request(const WAFRequest& request) {
    WAFResponse response;
    
    if (!config_.waf_enabled) {
        response.allowed = true;
        response.message = "WAF disabled";
        return response;
    }
    
    try {
        std::string json_payload = create_json_request(request);
        std::string http_response = make_http_request(json_payload);
        response = parse_json_response(http_response);
    } catch (const std::exception& e) {
        std::cerr << "WAF evaluation error: " << e.what() << std::endl;
        // Fail open - allow request if WAF is unreachable
        response.allowed = true;
        response.message = "WAF evaluation failed: " + std::string(e.what());
        last_health_status_ = false;
    }
    
    return response;
}

bool WAFClient::is_healthy() const {
    auto now = std::chrono::steady_clock::now();
    auto time_since_check = std::chrono::duration_cast<std::chrono::seconds>(now - last_health_check_);
    
    if (time_since_check.count() > HEALTH_CHECK_INTERVAL_SECONDS) {
        // Perform health check (in a real implementation, this would be async)
        return last_health_status_;
    }
    
    return last_health_status_;
}

std::string WAFClient::create_json_request(const WAFRequest& request) {
    std::ostringstream json;
    json << "{";
    json << "\"method\":\"" << request.method << "\",";
    json << "\"uri\":\"" << request.uri << "\",";
    json << "\"headers\":{";
    
    bool first_header = true;
    for (const auto& header : request.headers) {
        if (!first_header) json << ",";
        json << "\"" << header.first << "\":\"" << header.second << "\"";
        first_header = false;
    }
    
    json << "},";
    json << "\"body\":\"";
    
    // Escape JSON special characters in body
    for (char c : request.body) {
        switch (c) {
            case '"': json << "\\\""; break;
            case '\\': json << "\\\\"; break;
            case '\b': json << "\\b"; break;
            case '\f': json << "\\f"; break;
            case '\n': json << "\\n"; break;
            case '\r': json << "\\r"; break;
            case '\t': json << "\\t"; break;
            default: json << c; break;
        }
    }
    
    json << "\",";
    json << "\"remote_addr\":\"" << request.remote_addr << "\",";
    json << "\"server_addr\":\"" << request.server_addr << "\",";
    json << "\"server_port\":" << request.server_port;
    json << "}";
    
    return json.str();
}

WAFResponse WAFClient::parse_json_response(const std::string& response) {
    WAFResponse waf_response;
    
    // Simple JSON parsing - in production, use a proper JSON library like nlohmann/json
    std::regex allowed_regex(R"("allowed"\s*:\s*(true|false))");
    std::regex status_regex(R"("status_code"\s*:\s*(\d+))");
    std::regex message_regex(R"("message"\s*:\s*"([^"]*)")");
    std::regex rule_id_regex(R"("rule_id"\s*:\s*"([^"]*)")");
    
    std::smatch match;
    
    // Parse allowed field
    if (std::regex_search(response, match, allowed_regex)) {
        waf_response.allowed = (match[1].str() == "true");
    }
    
    // Parse status_code field
    if (std::regex_search(response, match, status_regex)) {
        waf_response.status_code = std::stoi(match[1].str());
    }
    
    // Parse message field
    if (std::regex_search(response, match, message_regex)) {
        waf_response.message = match[1].str();
    }
    
    // Parse rule_id field
    if (std::regex_search(response, match, rule_id_regex)) {
        waf_response.rule_id = match[1].str();
    }
    
    return waf_response;
}

std::string WAFClient::make_http_request(const std::string& json_payload) {
    tcp::resolver resolver(io_context_);
    auto endpoints = resolver.resolve(config_.waf_host, std::to_string(config_.waf_port));
    
    tcp::socket socket(io_context_);
    asio::connect(socket, endpoints);
    
    // Create HTTP request
    std::ostringstream request_stream;
    request_stream << "POST /evaluate HTTP/1.1\r\n";
    request_stream << "Host: " << config_.waf_host << ":" << config_.waf_port << "\r\n";
    request_stream << "Content-Type: application/json\r\n";
    request_stream << "Content-Length: " << json_payload.length() << "\r\n";
    request_stream << "Connection: close\r\n\r\n";
    request_stream << json_payload;
    
    std::string request = request_stream.str();
    
    // Send request
    asio::write(socket, asio::buffer(request));
    
    // Set timeout for reading response
    socket.async_wait(tcp::socket::wait_read, 
        [](const std::error_code& error) {
            if (error && error != asio::error::operation_aborted) {
                throw std::runtime_error("WAF request timeout");
            }
        }
    );
    
    // Read response
    asio::streambuf response_buffer;
    std::error_code error;
    
    // Set socket timeout
    socket.set_option(asio::detail::socket_option::integer<SOL_SOCKET, SO_RCVTIMEO>{config_.waf_timeout_ms});
    
    asio::read_until(socket, response_buffer, "\r\n\r\n", error);
    if (error && error != asio::error::eof) {
        throw std::runtime_error("Failed to read WAF response headers: " + error.message());
    }
    
    // Read the rest of the response body
    asio::read(socket, response_buffer, asio::transfer_all(), error);
    if (error && error != asio::error::eof) {
        throw std::runtime_error("Failed to read WAF response body: " + error.message());
    }
    
    std::string response_string{
        asio::buffers_begin(response_buffer.data()),
        asio::buffers_end(response_buffer.data())
    };
    
    // Extract JSON body from HTTP response
    size_t body_start = response_string.find("\r\n\r\n");
    if (body_start != std::string::npos) {
        std::string json_body = response_string.substr(body_start + 4);
        last_health_status_ = true;
        last_health_check_ = std::chrono::steady_clock::now();
        return json_body;
    }
    
    throw std::runtime_error("Invalid HTTP response format");
}