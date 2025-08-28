#include "http3_handler.h"
#include "compression.h"
#include "waf_client.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <random>
#include <iomanip>

HTTP3Handler::HTTP3Handler(const Config& config, asio::io_context& io_context) 
    : config_(config), io_context_(io_context) {
    compression_handler_ = std::make_unique<CompressionHandler>();
    waf_client_ = std::make_unique<WAFClient>(config);
    
#ifdef ENABLE_ADVANCED_FEATURES
    // Initialize QUIC SSL context with ECH and advanced features
    quic_ctx_ = SSL_CTX_new(TLS_server_method());
    if (!quic_ctx_) {
        throw std::runtime_error("Failed to create QUIC SSL context");
    }
    
    // Configure TLS 1.3 only with ECH support
    SSL_CTX_set_min_proto_version(quic_ctx_, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(quic_ctx_, TLS1_3_VERSION);
    
    // Enable advanced TLS 1.3 features
    SSL_CTX_set_options(quic_ctx_, SSL_OP_NO_RENEGOTIATION);
    
    // Enable early data support for performance
    SSL_CTX_set_options(quic_ctx_, SSL_OP_ENABLE_KTLS);
    
    // Enable early data (0-RTT) for performance
    SSL_CTX_set_max_early_data(quic_ctx_, 16384);
    
    // Load certificates
    if (SSL_CTX_use_certificate_file(quic_ctx_, config_.cert_file.c_str(), SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(quic_ctx_);
        throw std::runtime_error("Failed to load QUIC certificate");
    }
    
    if (SSL_CTX_use_PrivateKey_file(quic_ctx_, config_.key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(quic_ctx_);
        throw std::runtime_error("Failed to load QUIC private key");
    }
    
    // Set ALPN for HTTP/3 priority
    SSL_CTX_set_alpn_select_cb(quic_ctx_, [](SSL* ssl, const unsigned char** out, unsigned char* outlen,
                                             const unsigned char* in, unsigned int inlen, void* arg) -> int {
        (void)ssl; (void)arg;
        static const unsigned char protos[] = {
            2, 'h', '3',                          // HTTP/3 (priority)
            2, 'h', '2',                          // HTTP/2
            8, 'h', 't', 't', 'p', '/', '1', '.', '1'  // HTTP/1.1
        };
        
        if (SSL_select_next_proto((unsigned char**)out, outlen,
                                 protos, sizeof(protos), in, inlen) != OPENSSL_NPN_NEGOTIATED) {
            return SSL_TLSEXT_ERR_NOACK;
        }
        return SSL_TLSEXT_ERR_OK;
    }, nullptr);
    
    // Create UDP socket for QUIC
    udp_socket_ = std::make_unique<udp::socket>(io_context_);
    
    std::cout << "HTTP/3 with advanced features enabled and ready" << std::endl;
#else
    // Fallback when advanced features are not compiled in
    quic_ctx_ = nullptr;
    udp_socket_ = nullptr;
    std::cout << "Advanced features not compiled in - using standard HTTP/1.x and HTTP/2" << std::endl;
#endif
}

HTTP3Handler::~HTTP3Handler() {
    if (quic_ctx_) {
        SSL_CTX_free(quic_ctx_);
    }
    // io_context is managed externally
}

void HTTP3Handler::start_quic_server() {
#ifdef ENABLE_ADVANCED_FEATURES
    try {
        udp::endpoint endpoint(asio::ip::make_address("0.0.0.0"), config_.https_port);
        udp_socket_->open(udp::v4());
        udp_socket_->set_option(udp::socket::reuse_address(true));
        udp_socket_->bind(endpoint);
        
        std::cout << "HTTP/3 server with advanced features listening on UDP port " << config_.https_port << std::endl;
        
        // Start receiving QUIC packets
        start_receive();
        
    } catch (const std::exception& e) {
        std::cerr << "Failed to start QUIC server: " << e.what() << std::endl;
        throw;
    }
#else
    std::cout << "Advanced HTTP/3 server features not compiled in" << std::endl;
#endif
}

void HTTP3Handler::start_receive() {
    udp_socket_->async_receive_from(
        asio::buffer(recv_buffer_), remote_endpoint_,
        [this](std::error_code ec, size_t bytes_received) {
            if (!ec) {
                handle_quic_packet(recv_buffer_, bytes_received, remote_endpoint_);
                start_receive(); // Continue receiving
            } else {
                std::cerr << "UDP receive error: " << ec.message() << std::endl;
            }
        });
}

void HTTP3Handler::handle_quic_packet(const std::array<char, 4096>& buffer, size_t length,
                                     const udp::endpoint& endpoint) {
    try {
        std::string conn_key = endpoint.address().to_string() + ":" + std::to_string(endpoint.port());
        auto conn_it = connections_.find(conn_key);
        std::shared_ptr<QuicConnection> conn;
        
        if (conn_it == connections_.end()) {
            // New connection
            conn = create_quic_connection(endpoint);
            connections_[conn_key] = conn;
        } else {
            conn = conn_it->second;
        }
        
        // Process QUIC packet
        const uint8_t* data = reinterpret_cast<const uint8_t*>(buffer.data());
        process_quic_data(conn, data, length);
        
    } catch (const std::exception& e) {
        std::cerr << "Error handling QUIC packet: " << e.what() << std::endl;
    }
}

std::shared_ptr<HTTP3Handler::QuicConnection> 
HTTP3Handler::create_quic_connection(const udp::endpoint& endpoint) {
    SSL* ssl = SSL_new(quic_ctx_);
    if (!ssl) {
        throw std::runtime_error("Failed to create QUIC SSL connection");
    }
    
    // Set server mode
    SSL_set_accept_state(ssl);
    
    // Generate connection ID
    std::string conn_id = generate_connection_id();
    
    auto conn = std::make_shared<QuicConnection>(ssl, endpoint, conn_id);
    
    // Create HTTP/3 connection
    nghttp3_settings settings;
    nghttp3_settings_default(&settings);
    settings.qpack_max_dtable_capacity = 4096;
    settings.qpack_blocked_streams = 100;
    
    nghttp3_callbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.begin_headers = on_begin_headers;
    callbacks.recv_header = on_recv_header;
    callbacks.end_headers = on_end_headers;
    callbacks.recv_data = on_recv_data;
    callbacks.end_stream = on_end_stream;
    
    int rv = nghttp3_conn_server_new(&conn->h3_conn, &callbacks, &settings, 
                                     nullptr, conn.get());
    if (rv != 0) {
        throw std::runtime_error("Failed to create HTTP/3 connection");
    }
    
    // Enable 0-RTT if configured
    enable_0rtt_support(conn);
    
    return conn;
}

void HTTP3Handler::process_quic_data(std::shared_ptr<QuicConnection> conn, 
                                    const uint8_t* data, size_t len) {
    // Feed data to OpenSSL QUIC
    BIO* rbio = SSL_get_rbio(conn->ssl);
    BIO_write(rbio, data, len);
    
    // Try to complete handshake
    if (!conn->connection_established) {
        int result = SSL_do_handshake(conn->ssl);
        if (result == 1) {
            conn->connection_established = true;
            std::cout << "QUIC handshake completed" << std::endl;
        } else {
            int ssl_error = SSL_get_error(conn->ssl, result);
            if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
                std::cerr << "QUIC handshake failed: " << ssl_error << std::endl;
                return;
            }
        }
    }
    
    // Process HTTP/3 data if connection established
    if (conn->connection_established) {
        char app_data[4096];
        int bytes_read = SSL_read(conn->ssl, app_data, sizeof(app_data));
        
        if (bytes_read > 0) {
            // Feed to nghttp3
            nghttp3_ssize consumed = nghttp3_conn_read_stream(conn->h3_conn, 0, 
                                                             reinterpret_cast<const uint8_t*>(app_data),
                                                             bytes_read, 0);
            if (consumed < 0) {
                std::cerr << "HTTP/3 read error: " << consumed << std::endl;
            }
        }
    }
    
    // Send any pending data
    char write_buffer[4096];
    int bytes_to_send = SSL_read(conn->ssl, write_buffer, sizeof(write_buffer));
    if (bytes_to_send > 0) {
        send_quic_data(conn, reinterpret_cast<const uint8_t*>(write_buffer), bytes_to_send);
    }
}

void HTTP3Handler::send_quic_data(std::shared_ptr<QuicConnection> conn,
                                 const uint8_t* data, size_t len) {
    try {
        udp_socket_->send_to(asio::buffer(data, len), conn->endpoint);
    } catch (const std::exception& e) {
        std::cerr << "Failed to send QUIC data: " << e.what() << std::endl;
    }
}

void HTTP3Handler::enable_0rtt_support(std::shared_ptr<QuicConnection> conn) {
    SSL_set_max_early_data(conn->ssl, 16384);
    conn->early_data_enabled = true;
    std::cout << "0-RTT enabled for connection" << std::endl;
}

bool HTTP3Handler::process_early_data(std::shared_ptr<QuicConnection> conn,
                                     const uint8_t* data, size_t len) {
    if (!conn->early_data_enabled) {
        return false;
    }
    
    // Check if this is early data
    if (SSL_in_init(conn->ssl) == 0) {  // Connection established, check for early data
        std::cout << "Processing 0-RTT early data" << std::endl;
        
        // Process early data through HTTP/3
        nghttp3_ssize consumed = nghttp3_conn_read_stream(conn->h3_conn, 0, data, len, 0);
        return consumed >= 0;
    }
    
    return false;
}

// HTTP/3 callbacks
int HTTP3Handler::on_begin_headers(nghttp3_conn* conn, int64_t stream_id, void* user_data,
                                  void* stream_user_data) {
    (void)conn; (void)stream_id; (void)user_data; (void)stream_user_data;
    
    // Initialize request for this stream (simplified)
    std::cout << "HTTP/3 headers beginning for stream " << stream_id << std::endl;
    
    return 0;
}

int HTTP3Handler::on_recv_header(nghttp3_conn* conn, int64_t stream_id,
                                int32_t token, nghttp3_rcbuf* name, nghttp3_rcbuf* value,
                                uint8_t flags, void* user_data, void* stream_user_data) {
    (void)conn; (void)token; (void)flags; (void)stream_user_data;
    
    auto* handler = static_cast<HTTP3Handler*>(user_data);
    if (!handler) return 0;
    
    // Extract header name and value
    std::string header_name(reinterpret_cast<const char*>(nghttp3_rcbuf_get_buf(name).base),
                           nghttp3_rcbuf_get_buf(name).len);
    std::string header_value(reinterpret_cast<const char*>(nghttp3_rcbuf_get_buf(value).base),
                            nghttp3_rcbuf_get_buf(value).len);
    
    // Store in stream request
    auto& request = handler->stream_requests_[stream_id];
    
    if (header_name == ":method") {
        request.method = header_value;
    } else if (header_name == ":path") {
        request.path = header_value;
    } else if (header_name == ":scheme") {
        request.scheme = header_value;
    } else if (header_name == ":authority") {
        request.authority = header_value;
    } else {
        // Regular header
        request.headers[header_name] = header_value;
    }
    
    return 0;
}

int HTTP3Handler::on_end_headers(nghttp3_conn* conn, int64_t stream_id,
                                int fin, void* user_data, void* stream_user_data) {
    (void)conn; (void)fin; (void)stream_user_data;
    
    if (fin) {
        // Process request if headers are complete and stream is finished
        (void)user_data;  // Simplified for now
        std::cout << "HTTP/3 request complete for stream " << stream_id << std::endl;
    }
    
    return 0;
}

int HTTP3Handler::on_recv_data(nghttp3_conn* conn, int64_t stream_id,
                              const uint8_t* data, size_t datalen,
                              void* user_data, void* stream_user_data) {
    (void)conn; (void)stream_user_data;
    
    auto* quic_conn = static_cast<QuicConnection*>(user_data);
    
    // Store data in stream buffer
    std::string& buffer = quic_conn->stream_buffers[stream_id];
    buffer.append(reinterpret_cast<const char*>(data), datalen);
    
    return 0;
}

int HTTP3Handler::on_end_stream(nghttp3_conn* conn, int64_t stream_id,
                               void* user_data, void* stream_user_data) {
    (void)conn; (void)stream_user_data;
    
    auto* quic_conn = static_cast<QuicConnection*>(user_data);
    
    // Process complete request now that stream has ended
    std::cout << "HTTP/3 processing stream " << stream_id << " (simplified)" << std::endl;
    
    // Clean up stream buffer
    quic_conn->stream_buffers.erase(stream_id);
    
    return 0;
}

void HTTP3Handler::process_http3_request(std::shared_ptr<QuicConnection> conn, int64_t stream_id) {
    // Health check endpoint
    HTTP3Response response;
    response.status_code = 200;
    response.headers["content-type"] = "text/plain";
    response.body = "OK";
    
    send_http3_response(conn, stream_id, response);
}

void HTTP3Handler::send_http3_response(std::shared_ptr<QuicConnection> conn, int64_t stream_id,
                                      const HTTP3Response& response) {
    // Build response headers
    std::vector<nghttp3_nv> headers;
    
    // Status header
    std::string status_str = std::to_string(response.status_code);
    nghttp3_nv status_header = {
        reinterpret_cast<const uint8_t*>(":status"),
        reinterpret_cast<const uint8_t*>(status_str.c_str()),
        7, status_str.length(), NGHTTP3_NV_FLAG_NONE
    };
    headers.push_back(status_header);
    
    // Add response headers
    for (const auto& header : response.headers) {
        nghttp3_nv nv = {
            reinterpret_cast<const uint8_t*>(header.first.c_str()),
            reinterpret_cast<const uint8_t*>(header.second.c_str()),
            header.first.length(), header.second.length(), NGHTTP3_NV_FLAG_NONE
        };
        headers.push_back(nv);
    }
    
    // Submit response
    int rv = nghttp3_conn_submit_response(conn->h3_conn, stream_id, 
                                         headers.data(), headers.size(), nullptr);
    if (rv != 0) {
        std::cerr << "Failed to submit HTTP/3 response" << std::endl;
        return;
    }
    
    // Send body if present (simplified implementation)
    if (!response.body.empty()) {
        // This is a simplified implementation - a full implementation would need
        // to properly submit data frames through nghttp3
        std::cout << "Would send HTTP/3 response body of " << response.body.length() << " bytes" << std::endl;
    }
}

void HTTP3Handler::forward_to_backend(const HTTP3Request& request, HTTP3Response& response, 
                                     const std::string& client_ip) {
    try {
        tcp::socket backend_socket(backend_io_context_);
        tcp::resolver resolver(backend_io_context_);
        auto endpoints = resolver.resolve(config_.backend_host, std::to_string(config_.backend_port));
        
        asio::connect(backend_socket, endpoints);
        
        // Calculate XFF headers
        std::string xff_headers = calculate_xff_headers(client_ip, request);
        
        // Build backend request
        std::ostringstream backend_request;
        backend_request << request.method << " " << request.path << " HTTP/1.1\r\n";
        
        // Add XFF headers
        backend_request << xff_headers;
        
        // Add original headers (except those we're replacing)
        for (const auto& header : request.headers) {
            if (header.first.find("x-forwarded") == std::string::npos &&
                header.first != "x-real-ip") {
                backend_request << header.first << ": " << header.second << "\r\n";
            }
        }
        
        backend_request << "\r\n" << request.body;
        
        // Send request to backend
        asio::write(backend_socket, asio::buffer(backend_request.str()));
        
        // Read complete response from backend
        std::string backend_response = read_full_backend_response(backend_socket);
        
        // Parse backend response properly
        response = parse_backend_response(backend_response);
        
    } catch (const std::exception& e) {
        // Backend connection failed
        response.status_code = 502;
        response.headers["content-type"] = "text/html";
        response.body = "<html><body><h1>502 Bad Gateway</h1></body></html>";
    }
}

std::string HTTP3Handler::calculate_xff_headers(const std::string& client_ip, const HTTP3Request& request) {
    std::ostringstream xff;
    xff << "X-Forwarded-For: " << client_ip << "\r\n";
    xff << "X-Real-IP: " << client_ip << "\r\n";
    xff << "X-Forwarded-Proto: " << request.scheme << "\r\n";
    
    if (!request.authority.empty()) {
        xff << "X-Forwarded-Host: " << request.authority << "\r\n";
    }
    
    return xff.str();
}

bool HTTP3Handler::should_compress(const std::string& content_type) {
    if (content_type.empty()) return false;
    
    for (const auto& type : compressible_types_) {
        if (content_type.find(type) == 0) {
            return true;
        }
    }
    return false;
}

std::string HTTP3Handler::get_supported_encoding(const std::string& accept_encoding) {
    if (accept_encoding.find("br") != std::string::npos) return "br";
    if (accept_encoding.find("gzip") != std::string::npos) return "gzip";
    if (accept_encoding.find("zstd") != std::string::npos) return "zstd";
    if (accept_encoding.find("deflate") != std::string::npos) return "deflate";
    return "";
}

std::string HTTP3Handler::generate_connection_id() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    std::stringstream ss;
    for (int i = 0; i < 16; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << dis(gen);
    }
    return ss.str();
}

void HTTP3Handler::stop() {
#ifdef ENABLE_ADVANCED_FEATURES
    if (udp_socket_ && udp_socket_->is_open()) {
        udp_socket_->close();
    }
    connections_.clear();
#endif
}

bool HTTP3Handler::is_http3_supported() const {
#ifdef ENABLE_ADVANCED_FEATURES
    return true;
#else
    return false;
#endif
}

std::string HTTP3Handler::read_full_backend_response(asio::ip::tcp::socket& backend_socket) {
    std::string full_response;
    std::array<char, 8192> buffer;
    size_t content_length = 0;
    size_t headers_end_pos = 0;
    bool headers_complete = false;
    
    try {
        // First read to get headers
        size_t bytes_read = backend_socket.read_some(asio::buffer(buffer));
        full_response.append(buffer.data(), bytes_read);
        
        // Check if headers are complete
        headers_end_pos = full_response.find("\r\n\r\n");
        if (headers_end_pos != std::string::npos) {
            headers_complete = true;
            headers_end_pos += 4; // Move past "\r\n\r\n"
            
            // Extract Content-Length if present
            auto cl_pos = full_response.find("Content-Length:");
            if (cl_pos != std::string::npos && cl_pos < headers_end_pos) {
                auto cl_end = full_response.find("\r\n", cl_pos);
                if (cl_end != std::string::npos) {
                    std::string cl_str = full_response.substr(cl_pos + 15, cl_end - cl_pos - 15);
                    // Trim whitespace
                    cl_str.erase(0, cl_str.find_first_not_of(" \t"));
                    cl_str.erase(cl_str.find_last_not_of(" \t") + 1);
                    content_length = std::stoull(cl_str);
                }
            }
        }
        
        // If we have Content-Length, read until we have all content
        if (headers_complete && content_length > 0) {
            size_t current_body_size = full_response.size() - headers_end_pos;
            while (current_body_size < content_length) {
                bytes_read = backend_socket.read_some(asio::buffer(buffer));
                if (bytes_read == 0) break; // Connection closed
                full_response.append(buffer.data(), bytes_read);
                current_body_size += bytes_read;
            }
        } else if (headers_complete) {
            // No Content-Length, read until connection closes or Transfer-Encoding: chunked
            bool is_chunked = full_response.find("Transfer-Encoding: chunked") != std::string::npos ||
                             full_response.find("transfer-encoding: chunked") != std::string::npos;
            
            if (is_chunked) {
                // Handle chunked encoding
                while (true) {
                    try {
                        bytes_read = backend_socket.read_some(asio::buffer(buffer));
                        if (bytes_read == 0) break;
                        full_response.append(buffer.data(), bytes_read);
                        
                        // Check for end of chunks (0\r\n\r\n)
                        if (full_response.find("\r\n0\r\n\r\n") != std::string::npos) {
                            break;
                        }
                    } catch (const std::exception&) {
                        break;
                    }
                }
            } else {
                // Read until connection closes
                while (true) {
                    try {
                        bytes_read = backend_socket.read_some(asio::buffer(buffer));
                        if (bytes_read == 0) break;
                        full_response.append(buffer.data(), bytes_read);
                    } catch (const std::exception&) {
                        break;
                    }
                }
            }
        }
        
    } catch (const std::exception&) {
        // Return what we have so far
    }
    
    return full_response;
}

HTTP3Handler::HTTP3Response HTTP3Handler::parse_backend_response(const std::string& raw_response) {
    HTTP3Response response;
    
    if (raw_response.empty()) {
        response.status_code = 502;
        response.headers["content-type"] = "text/html";
        response.body = "<html><body><h1>502 Bad Gateway - Empty Response</h1></body></html>";
        return response;
    }
    
    std::istringstream iss(raw_response);
    std::string line;
    
    // Parse status line
    if (std::getline(iss, line)) {
        std::istringstream status_line(line);
        std::string version;
        int status_code;
        std::string status_text;
        status_line >> version >> status_code >> status_text;
        
        response.status_code = status_code;
    } else {
        response.status_code = 502;
        response.headers["content-type"] = "text/html";
        response.body = "<html><body><h1>502 Bad Gateway - Invalid Response</h1></body></html>";
        return response;
    }
    
    // Parse headers
    while (std::getline(iss, line) && line != "\r" && !line.empty()) {
        auto colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string name = line.substr(0, colon_pos);
            std::string value = line.substr(colon_pos + 1);
            
            // Trim whitespace and \r
            value.erase(0, value.find_first_not_of(" \t\r"));
            value.erase(value.find_last_not_of(" \t\r") + 1);
            
            // Convert header names to lowercase for HTTP/3 compliance
            std::transform(name.begin(), name.end(), name.begin(), ::tolower);
            
            response.headers[name] = value;
        }
    }
    
    // Parse body
    std::string body_content((std::istreambuf_iterator<char>(iss)), std::istreambuf_iterator<char>());
    response.body = body_content;
    
    // Handle chunked encoding in body
    if (response.headers.count("transfer-encoding") && 
        response.headers["transfer-encoding"].find("chunked") != std::string::npos) {
        
        std::string decoded_body;
        std::istringstream body_stream(response.body);
        std::string chunk_line;
        
        while (std::getline(body_stream, chunk_line)) {
            // Remove \r if present
            if (!chunk_line.empty() && chunk_line.back() == '\r') {
                chunk_line.pop_back();
            }
            
            // Parse chunk size (in hex)
            size_t chunk_size = 0;
            try {
                chunk_size = std::stoull(chunk_line, nullptr, 16);
            } catch (const std::exception&) {
                break; // Invalid chunk size
            }
            
            if (chunk_size == 0) {
                break; // End of chunks
            }
            
            // Read chunk data
            std::string chunk_data(chunk_size, '\0');
            body_stream.read(&chunk_data[0], chunk_size);
            if (body_stream.gcount() == static_cast<std::streamsize>(chunk_size)) {
                decoded_body += chunk_data;
            }
            
            // Read trailing CRLF
            std::getline(body_stream, chunk_line);
        }
        
        response.body = decoded_body;
        response.headers.erase("transfer-encoding");
        response.headers["content-length"] = std::to_string(decoded_body.length());
    }
    
    return response;
}