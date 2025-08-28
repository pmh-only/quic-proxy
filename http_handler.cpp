#include "http_handler.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <regex>

HTTPHandler::HTTPHandler(const Config& config) 
    : config_(config) {
    compression_handler_ = std::make_unique<CompressionHandler>();
    waf_client_ = std::make_unique<WAFClient>(config);
}

void HTTPHandler::handle_http_connection(std::shared_ptr<tcp::socket> socket) {
    auto buffer = std::make_shared<std::array<char, 8192>>();
    
    socket->async_read_some(asio::buffer(*buffer),
        [this, socket, buffer](std::error_code ec, std::size_t bytes_read) {
            if (ec) return;
            
            std::string request_data(buffer->data(), bytes_read);
            HTTPRequest request = parse_request(request_data);
            
            std::string client_ip = socket->remote_endpoint().address().to_string();
            
            // Health check endpoint
            if (request.path == "/_gwhealthz") {
                HTTPResponse response = create_health_check_response();
                std::string response_str = serialize_response(response);
                asio::async_write(*socket, asio::buffer(response_str),
                    [socket](std::error_code ec, std::size_t) {});
                return;
            }
            
            // Redirect HTTP to HTTPS
            std::string host = request.headers.count("Host") ? request.headers["Host"] : "localhost";
            HTTPResponse redirect = create_redirect_response(host, request.path);
            std::string response_str = serialize_response(redirect);
            asio::async_write(*socket, asio::buffer(response_str),
                [socket](std::error_code ec, std::size_t) {});
        });
}

void HTTPHandler::handle_https_connection(std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_socket) {
    ssl_socket->async_handshake(asio::ssl::stream_base::server,
        [this, ssl_socket](std::error_code ec) {
            if (ec) return;
            
            auto buffer = std::make_shared<std::array<char, 8192>>();
            ssl_socket->async_read_some(asio::buffer(*buffer),
                [this, ssl_socket, buffer](std::error_code ec, std::size_t bytes_read) {
                    if (ec) return;
                    
                    std::string request_data(buffer->data(), bytes_read);
                    HTTPRequest request = parse_request(request_data);
                    
                    std::string client_ip = ssl_socket->lowest_layer().remote_endpoint().address().to_string();
                    process_ssl_request(ssl_socket, request, client_ip);
                });
        });
}

HTTPHandler::HTTPRequest HTTPHandler::parse_request(const std::string& raw_request) {
    HTTPRequest request;
    std::istringstream iss(raw_request);
    std::string line;
    
    // Parse request line
    if (std::getline(iss, line)) {
        std::istringstream request_line(line);
        request_line >> request.method >> request.path >> request.version;
    }
    
    // Parse headers
    while (std::getline(iss, line) && line != "\r" && !line.empty()) {
        auto colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string name = line.substr(0, colon_pos);
            std::string value = line.substr(colon_pos + 1);
            
            // Trim whitespace
            value.erase(0, value.find_first_not_of(" \t\r"));
            value.erase(value.find_last_not_of(" \t\r") + 1);
            
            request.headers[name] = value;
        }
    }
    
    // Check for WebSocket upgrade
    if (request.headers.count("Connection") && request.headers.count("Upgrade")) {
        std::string connection = request.headers["Connection"];
        std::string upgrade = request.headers["Upgrade"];
        std::transform(connection.begin(), connection.end(), connection.begin(), ::tolower);
        std::transform(upgrade.begin(), upgrade.end(), upgrade.begin(), ::tolower);
        
        if (connection.find("upgrade") != std::string::npos && upgrade == "websocket") {
            request.is_websocket_upgrade = true;
        }
    }
    
    // Parse body if present
    std::string remaining((std::istreambuf_iterator<char>(iss)), std::istreambuf_iterator<char>());
    request.body = remaining;
    
    return request;
}

HTTPHandler::HTTPResponse HTTPHandler::create_health_check_response() {
    HTTPResponse response;
    response.status_code = 200;
    response.status_text = "OK";
    response.headers["Content-Type"] = "text/plain";
    response.headers["Content-Length"] = "2";
    response.body = "OK";
    return response;
}

HTTPHandler::HTTPResponse HTTPHandler::create_redirect_response(const std::string& host, const std::string& path) {
    HTTPResponse response;
    response.status_code = 301;
    response.status_text = "Moved Permanently";
    std::string location = "https://" + host + path;
    response.headers["Location"] = location;
    response.headers["Content-Length"] = "0";
    return response;
}

void HTTPHandler::process_ssl_request(std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_socket, 
                                     const HTTPRequest& request, const std::string& client_ip) {
    
    // Health check endpoint
    if (request.path == "/_gwhealthz") {
        HTTPResponse response = create_health_check_response();
        std::string response_str = serialize_response(response);
        asio::async_write(*ssl_socket, asio::buffer(response_str),
            [ssl_socket](std::error_code ec, std::size_t) {});
        return;
    }
    
    // WAF Evaluation
    HTTPResponse waf_rejection_response;
    if (!evaluate_waf_request(request, client_ip, waf_rejection_response)) {
        // Request blocked by WAF
        std::string response_str = serialize_response(waf_rejection_response);
        asio::async_write(*ssl_socket, asio::buffer(response_str),
            [ssl_socket](std::error_code ec, std::size_t) {});
        return;
    }
    
    // Handle WebSocket upgrade
    if (request.is_websocket_upgrade) {
        // WebSocket handling would require more complex implementation
        // For now, we'll forward to backend
    }
    
    // Calculate XFF headers
    std::string xff_headers = calculate_xff_headers(client_ip, request);
    
    // Forward request to backend
    HTTPResponse response;
    forward_to_backend(request, response, xff_headers);
    
    // Apply compression if needed
    if (should_compress(response.headers["Content-Type"])) {
        std::string accept_encoding = request.headers.count("Accept-Encoding") ? 
                                    request.headers.at("Accept-Encoding") : "";
        std::string encoding = get_supported_encoding(accept_encoding);
        
        if (!encoding.empty()) {
            std::string compressed = compression_handler_->compress(response.body, encoding);
            if (!compressed.empty()) {
                response.body = compressed;
                response.headers["Content-Encoding"] = encoding;
                response.headers["Content-Length"] = std::to_string(compressed.length());
            }
        }
    }
    
    std::string response_str = serialize_response(response);
    asio::async_write(*ssl_socket, asio::buffer(response_str),
        [ssl_socket](std::error_code ec, std::size_t) {});
}

std::string HTTPHandler::calculate_xff_headers(const std::string& client_ip, const HTTPRequest& request) {
    // Ignore any existing X-Forwarded-For headers from client
    std::ostringstream xff;
    xff << "X-Forwarded-For: " << client_ip << "\r\n";
    xff << "X-Real-IP: " << client_ip << "\r\n";
    xff << "X-Forwarded-Proto: https\r\n";
    
    if (request.headers.count("Host")) {
        xff << "X-Forwarded-Host: " << request.headers.at("Host") << "\r\n";
    }
    
    return xff.str();
}

bool HTTPHandler::should_compress(const std::string& content_type) {
    if (content_type.empty()) return false;
    
    for (const auto& type : compressible_types_) {
        if (content_type.find(type) == 0) {
            return true;
        }
    }
    return false;
}

std::string HTTPHandler::get_supported_encoding(const std::string& accept_encoding) {
    if (accept_encoding.find("br") != std::string::npos) return "br";
    if (accept_encoding.find("gzip") != std::string::npos) return "gzip";
    if (accept_encoding.find("zstd") != std::string::npos) return "zstd";
    if (accept_encoding.find("deflate") != std::string::npos) return "deflate";
    return "";
}

void HTTPHandler::forward_to_backend(const HTTPRequest& request, HTTPResponse& response, const std::string& xff_headers) {
    // This is a simplified backend forwarding
    // In a real implementation, this would establish a connection to the backend
    try {
        tcp::socket backend_socket(backend_io_context_);
        tcp::resolver resolver(backend_io_context_);
        auto endpoints = resolver.resolve(config_.backend_host, std::to_string(config_.backend_port));
        
        asio::connect(backend_socket, endpoints);
        
        // Build backend request
        std::ostringstream backend_request;
        backend_request << request.method << " " << request.path << " " << request.version << "\r\n";
        
        // Add XFF headers
        backend_request << xff_headers;
        
        // Add original headers (except those we're replacing)
        for (const auto& header : request.headers) {
            if (header.first.find("X-Forwarded") == std::string::npos &&
                header.first != "X-Real-IP") {
                backend_request << header.first << ": " << header.second << "\r\n";
            }
        }
        
        backend_request << "\r\n" << request.body;
        
        // Send request to backend
        asio::write(backend_socket, asio::buffer(backend_request.str()));
        
        // Read response from backend
        std::array<char, 8192> buffer;
        size_t bytes_read = backend_socket.read_some(asio::buffer(buffer));
        
        std::string backend_response(buffer.data(), bytes_read);
        
        // Parse backend response (simplified)
        response.status_code = 200;
        response.status_text = "OK";
        response.headers["Content-Type"] = "text/html";
        response.body = backend_response;
        
    } catch (const std::exception& e) {
        // Backend connection failed
        response.status_code = 502;
        response.status_text = "Bad Gateway";
        response.headers["Content-Type"] = "text/html";
        response.body = "<html><body><h1>502 Bad Gateway</h1></body></html>";
    }
}

bool HTTPHandler::evaluate_waf_request(const HTTPRequest& request, const std::string& client_ip, HTTPResponse& waf_rejection_response) {
    if (!waf_client_->is_waf_enabled()) {
        return true; // WAF disabled, allow all requests
    }
    
    // Build WAF request
    WAFRequest waf_request;
    waf_request.method = request.method;
    waf_request.uri = request.path;
    waf_request.headers = request.headers;
    waf_request.body = request.body;
    waf_request.remote_addr = client_ip;
    waf_request.server_addr = "0.0.0.0"; // Could be made configurable
    waf_request.server_port = config_.https_port;
    
    // Evaluate request with WAF
    WAFResponse waf_response = waf_client_->evaluate_request(waf_request);
    
    if (!waf_response.allowed) {
        // Create rejection response
        waf_rejection_response.status_code = waf_response.status_code > 0 ? waf_response.status_code : 403;
        waf_rejection_response.status_text = "Forbidden";
        waf_rejection_response.headers["Content-Type"] = "text/html";
        waf_rejection_response.headers["X-WAF-Rule-ID"] = waf_response.rule_id;
        
        std::ostringstream body;
        body << "<html><head><title>Access Denied</title></head><body>";
        body << "<h1>403 - Access Denied</h1>";
        body << "<p>Your request has been blocked by our Web Application Firewall.</p>";
        if (!waf_response.message.empty()) {
            body << "<p>Reason: " << waf_response.message << "</p>";
        }
        if (!waf_response.rule_id.empty()) {
            body << "<p>Rule ID: " << waf_response.rule_id << "</p>";
        }
        body << "</body></html>";
        
        waf_rejection_response.body = body.str();
        waf_rejection_response.headers["Content-Length"] = std::to_string(waf_rejection_response.body.length());
        
        // Log the blocked request
        std::cout << "WAF BLOCKED: " << client_ip << " " << request.method << " " << request.path 
                  << " - Rule: " << waf_response.rule_id << " - " << waf_response.message << std::endl;
        
        return false;
    }
    
    return true; // Request allowed
}

std::string HTTPHandler::serialize_response(const HTTPResponse& response) {
    std::ostringstream oss;
    oss << "HTTP/1.1 " << response.status_code << " " << response.status_text << "\r\n";
    
    for (const auto& header : response.headers) {
        oss << header.first << ": " << header.second << "\r\n";
    }
    
    oss << "\r\n" << response.body;
    return oss.str();
}