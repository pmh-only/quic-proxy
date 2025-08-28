#include "http2_handler.h"
#include "compression.h"
#include "waf_client.h"
#include <iostream>
#include <sstream>
#include <algorithm>

HTTP2Handler::HTTP2Handler(const Config& config) : config_(config) {
    compression_handler_ = std::make_unique<CompressionHandler>();
    waf_client_ = std::make_unique<WAFClient>(config);
}

HTTP2Handler::~HTTP2Handler() = default;

void HTTP2Handler::handle_http2_connection(std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_socket) {
    auto session = std::make_shared<HTTP2Session>(ssl_socket, this);
    session_stream_requests_[session.get()] = std::unordered_map<int32_t, HTTP2Request>();
    active_sessions_[session.get()] = session;
    start_session(session);
}

void HTTP2Handler::start_session(std::shared_ptr<HTTP2Session> session) {
    nghttp2_session_callbacks* callbacks;
    nghttp2_session_callbacks_new(&callbacks);
    
    nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_callback);
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, on_begin_headers_callback);
    
    nghttp2_session_server_new(&session->session, callbacks, session.get());
    nghttp2_session_callbacks_del(callbacks);
    
    // Send connection preface (HTTP/2 settings frame)
    nghttp2_settings_entry settings[] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100},
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 65536},
        {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, 16384}
    };
    
    nghttp2_submit_settings(session->session, NGHTTP2_FLAG_NONE, settings, 3);
    
    read_data(session);
}

void HTTP2Handler::read_data(std::shared_ptr<HTTP2Session> session) {
    if (session->session_terminated) return;
    
    auto buffer = std::make_shared<std::array<char, 8192>>();
    session->ssl_socket->async_read_some(asio::buffer(*buffer),
        [this, session, buffer](std::error_code ec, std::size_t bytes_read) {
            if (ec || session->session_terminated) {
                session->session_terminated = true;
                session_stream_requests_.erase(session.get());
                active_sessions_.erase(session.get());
                return;
            }
            
            ssize_t readlen = nghttp2_session_mem_recv(session->session, 
                                                      reinterpret_cast<const uint8_t*>(buffer->data()),
                                                      bytes_read);
            
            if (readlen < 0) {
                std::cerr << "HTTP/2 session error: " << nghttp2_strerror(readlen) << std::endl;
                session->session_terminated = true;
                session_stream_requests_.erase(session.get());
                active_sessions_.erase(session.get());
                return;
            }
            
            if (nghttp2_session_want_write(session->session)) {
                write_data(session);
            }
            
            if (!session->session_terminated) {
                read_data(session);
            }
        });
}

void HTTP2Handler::write_data(std::shared_ptr<HTTP2Session> session) {
    if (session->session_terminated || session->write_pending) return;
    
    const uint8_t* data;
    ssize_t datalen = nghttp2_session_mem_send(session->session, &data);
    
    if (datalen > 0) {
        session->write_pending = true;
        session->write_buffer.assign(reinterpret_cast<const char*>(data), datalen);
        
        asio::async_write(*session->ssl_socket, asio::buffer(session->write_buffer),
            [this, session](std::error_code ec, std::size_t) {
                session->write_pending = false;
                if (ec) {
                    session->session_terminated = true;
                    return;
                }
                
                if (nghttp2_session_want_write(session->session)) {
                    write_data(session);
                }
            });
    } else if (datalen < 0) {
        std::cerr << "HTTP/2 session send error: " << nghttp2_strerror(datalen) << std::endl;
        session->session_terminated = true;
    }
}

ssize_t HTTP2Handler::send_callback(nghttp2_session* session, const uint8_t* data,
                                   size_t length, int flags, void* user_data) {
    (void)session; (void)flags; (void)data; (void)length; (void)user_data;
    
    // Return NGHTTP2_ERR_WOULDBLOCK to use nghttp2_session_mem_send instead
    // This prevents double-writing to the socket
    return NGHTTP2_ERR_WOULDBLOCK;
}

int HTTP2Handler::on_frame_recv_callback(nghttp2_session* session,
                                        const nghttp2_frame* frame, void* user_data) {
    auto* h2_session = static_cast<HTTP2Session*>(user_data);
    
    switch (frame->hd.type) {
        case NGHTTP2_DATA:
            if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
                // Process request when stream ends
                auto session_shared = h2_session->handler_ptr->find_session_by_ptr(h2_session);
                if (session_shared) {
                    h2_session->handler_ptr->process_request(session_shared, frame->hd.stream_id);
                }
            }
            break;
        case NGHTTP2_HEADERS:
            if (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS) {
                if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
                    // Process request when headers end and stream ends
                    auto session_shared = h2_session->handler_ptr->find_session_by_ptr(h2_session);
                    if (session_shared) {
                        h2_session->handler_ptr->process_request(session_shared, frame->hd.stream_id);
                    }
                }
            }
            break;
    }
    
    return 0;
}

int HTTP2Handler::on_data_chunk_recv_callback(nghttp2_session* session, uint8_t flags,
                                             int32_t stream_id, const uint8_t* data,
                                             size_t len, void* user_data) {
    (void)session; (void)flags;
    auto* h2_session = static_cast<HTTP2Session*>(user_data);
    
    // Store data in stream request body
    auto& session_requests = h2_session->handler_ptr->session_stream_requests_[h2_session];
    if (session_requests.find(stream_id) != session_requests.end()) {
        session_requests[stream_id].body.append(reinterpret_cast<const char*>(data), len);
    }
    return 0;
}

int HTTP2Handler::on_stream_close_callback(nghttp2_session* session, int32_t stream_id,
                                          uint32_t error_code, void* user_data) {
    (void)session; (void)error_code;
    auto* h2_session = static_cast<HTTP2Session*>(user_data);
    
    // Clean up stream data
    auto& session_requests = h2_session->handler_ptr->session_stream_requests_[h2_session];
    session_requests.erase(stream_id);
    
    return 0;
}

int HTTP2Handler::on_header_callback(nghttp2_session* session, const nghttp2_frame* frame,
                                    const uint8_t* name, size_t namelen,
                                    const uint8_t* value, size_t valuelen,
                                    uint8_t flags, void* user_data) {
    (void)session; (void)flags;
    
    if (frame->hd.type != NGHTTP2_HEADERS) {
        return 0;
    }
    
    auto* h2_session = static_cast<HTTP2Session*>(user_data);
    
    std::string header_name(reinterpret_cast<const char*>(name), namelen);
    std::string header_value(reinterpret_cast<const char*>(value), valuelen);
    
    // Store headers in request object
    auto& session_requests = h2_session->handler_ptr->session_stream_requests_[h2_session];
    auto& request = session_requests[frame->hd.stream_id];
    
    if (header_name == ":method") {
        request.method = header_value;
    } else if (header_name == ":path") {
        request.path = header_value;
    } else if (header_name == ":scheme") {
        request.scheme = header_value;
    } else if (header_name == ":authority") {
        request.authority = header_value;
    } else {
        request.headers[header_name] = header_value;
    }
    
    return 0;
}

int HTTP2Handler::on_begin_headers_callback(nghttp2_session* session,
                                           const nghttp2_frame* frame, void* user_data) {
    (void)session;
    
    if (frame->hd.type != NGHTTP2_HEADERS) {
        return 0;
    }
    
    // Initialize request for this stream
    auto* h2_session = static_cast<HTTP2Session*>(user_data);
    auto& session_requests = h2_session->handler_ptr->session_stream_requests_[h2_session];
    session_requests[frame->hd.stream_id] = HTTP2Request{};
    
    return 0;
}

void HTTP2Handler::process_request(std::shared_ptr<HTTP2Session> session, int32_t stream_id) {
    auto& session_requests = session_stream_requests_[session.get()];
    auto request_it = session_requests.find(stream_id);
    if (request_it == session_requests.end()) {
        return;
    }
    
    HTTP2Request& request = request_it->second;
    std::string client_ip = session->ssl_socket->lowest_layer().remote_endpoint().address().to_string();
    
    // Health check endpoint
    if (request.path == "/_gwhealthz") {
        HTTP2Response response;
        response.status_code = 200;
        response.headers["content-type"] = "text/plain";
        response.body = "OK";
        send_response(session, stream_id, response);
        session_requests.erase(request_it);
        return;
    }
    
    // Process normal request
    HTTP2Response response;
    forward_to_backend(request, response, client_ip);
    
    // Apply compression if needed
    if (should_compress(response.headers["content-type"])) {
        std::string accept_encoding = request.headers.count("accept-encoding") ? 
                                    request.headers.at("accept-encoding") : "";
        std::string encoding = get_supported_encoding(accept_encoding);
        
        if (!encoding.empty()) {
            std::string compressed = compression_handler_->compress(response.body, encoding);
            if (!compressed.empty()) {
                response.body = compressed;
                response.headers["content-encoding"] = encoding;
            }
        }
    }
    
    send_response(session, stream_id, response);
    session_requests.erase(request_it);
}

void HTTP2Handler::forward_to_backend(const HTTP2Request& request, HTTP2Response& response, const std::string& client_ip) {
    try {
        tcp::socket backend_socket(backend_io_context_);
        tcp::resolver resolver(backend_io_context_);
        auto endpoints = resolver.resolve(config_.backend_host, std::to_string(config_.backend_port));
        
        asio::connect(backend_socket, endpoints);
        
        // Build backend request as HTTP/1.1
        std::ostringstream backend_request;
        backend_request << request.method << " " << request.path << " HTTP/1.1\r\n";
        
        // Add XFF headers
        backend_request << calculate_xff_headers(client_ip, request);
        
        // Add Host header
        if (!request.authority.empty()) {
            backend_request << "Host: " << request.authority << "\r\n";
        }
        
        // Add original headers (except HTTP/2 pseudo headers)
        for (const auto& header : request.headers) {
            if (header.first[0] != ':' && header.first.find("x-forwarded") == std::string::npos &&
                header.first != "x-real-ip") {
                backend_request << header.first << ": " << header.second << "\r\n";
            }
        }
        
        if (!request.body.empty()) {
            backend_request << "Content-Length: " << request.body.length() << "\r\n";
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

void HTTP2Handler::send_response(std::shared_ptr<HTTP2Session> session, int32_t stream_id, const HTTP2Response& response) {
    // Build response headers
    std::vector<nghttp2_nv> headers;
    
    // Status header
    std::string status_str = std::to_string(response.status_code);
    nghttp2_nv status_header = {
        const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(":status")),
        const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(status_str.c_str())),
        7, status_str.length(), NGHTTP2_NV_FLAG_NONE
    };
    headers.push_back(status_header);
    
    // Add response headers
    for (const auto& header : response.headers) {
        nghttp2_nv nv = {
            const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(header.first.c_str())),
            const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(header.second.c_str())),
            header.first.length(), header.second.length(), NGHTTP2_NV_FLAG_NONE
        };
        headers.push_back(nv);
    }
    
    if (response.body.empty()) {
        nghttp2_submit_response(session->session, stream_id, headers.data(), headers.size(), nullptr);
    } else {
        // Store body in session for data callback access
        session->response_bodies[stream_id] = response.body;
        
        nghttp2_data_provider data_prd;
        data_prd.source.ptr = &session->response_bodies[stream_id];
        data_prd.read_callback = [](nghttp2_session* nghttp2_session, int32_t callback_stream_id,
                                   uint8_t* buf, size_t length, uint32_t* data_flags,
                                   nghttp2_data_source* source, void* user_data) -> ssize_t {
            (void)nghttp2_session; (void)user_data;
            
            auto* body = static_cast<std::string*>(source->ptr);
            if (body->empty()) {
                *data_flags |= NGHTTP2_DATA_FLAG_EOF;
                
                // Clean up stored body when done
                auto* h2_session = static_cast<HTTP2Session*>(user_data);
                if (h2_session) {
                    h2_session->response_bodies.erase(callback_stream_id);
                }
                
                return 0;
            }
            
            size_t copy_len = std::min(length, body->length());
            std::memcpy(buf, body->data(), copy_len);
            body->erase(0, copy_len);
            
            if (body->empty()) {
                *data_flags |= NGHTTP2_DATA_FLAG_EOF;
                
                // Clean up stored body when done
                auto* h2_session = static_cast<HTTP2Session*>(user_data);
                if (h2_session) {
                    h2_session->response_bodies.erase(callback_stream_id);
                }
            }
            
            return copy_len;
        };
        
        nghttp2_submit_response(session->session, stream_id, headers.data(), headers.size(), &data_prd);
    }
    
    if (nghttp2_session_want_write(session->session)) {
        write_data(session);
    }
}

std::string HTTP2Handler::calculate_xff_headers(const std::string& client_ip, const HTTP2Request& request) {
    std::ostringstream xff;
    xff << "X-Forwarded-For: " << client_ip << "\r\n";
    xff << "X-Real-IP: " << client_ip << "\r\n";
    xff << "X-Forwarded-Proto: " << request.scheme << "\r\n";
    
    if (!request.authority.empty()) {
        xff << "X-Forwarded-Host: " << request.authority << "\r\n";
    }
    
    return xff.str();
}

bool HTTP2Handler::should_compress(const std::string& content_type) {
    if (content_type.empty()) return false;
    
    for (const auto& type : compressible_types_) {
        if (content_type.find(type) == 0) {
            return true;
        }
    }
    return false;
}

std::string HTTP2Handler::get_supported_encoding(const std::string& accept_encoding) {
    if (accept_encoding.find("br") != std::string::npos) return "br";
    if (accept_encoding.find("gzip") != std::string::npos) return "gzip";
    if (accept_encoding.find("zstd") != std::string::npos) return "zstd";
    if (accept_encoding.find("deflate") != std::string::npos) return "deflate";
    return "";
}

std::shared_ptr<HTTP2Handler::HTTP2Session> HTTP2Handler::find_session_by_ptr(HTTP2Session* raw_ptr) {
    auto it = active_sessions_.find(raw_ptr);
    return (it != active_sessions_.end()) ? it->second : nullptr;
}

std::string HTTP2Handler::read_full_backend_response(tcp::socket& backend_socket) {
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

HTTP2Handler::HTTP2Response HTTP2Handler::parse_backend_response(const std::string& raw_response) {
    HTTP2Response response;
    
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
        
        // Read rest of status text if it contains spaces
        std::string remaining;
        while (status_line >> remaining) {
            status_text += " " + remaining;
        }
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
            
            // Convert header names to lowercase for HTTP/2 compliance
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