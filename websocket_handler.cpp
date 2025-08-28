#include "websocket_handler.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>

const std::string WebSocketHandler::WEBSOCKET_MAGIC_STRING = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

WebSocketHandler::WebSocketHandler() {
}

std::string WebSocketHandler::generate_websocket_accept(const std::string& websocket_key) {
    std::string combined = websocket_key + WEBSOCKET_MAGIC_STRING;
    
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(combined.c_str()), combined.length(), hash);
    
    // Base64 encode
    std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    
    for (int i = 0; i < SHA_DIGEST_LENGTH; i += 3) {
        unsigned int val = (hash[i] << 16) | 
                          (i + 1 < SHA_DIGEST_LENGTH ? hash[i + 1] << 8 : 0) |
                          (i + 2 < SHA_DIGEST_LENGTH ? hash[i + 2] : 0);
        
        result += base64_chars[(val >> 18) & 0x3F];
        result += base64_chars[(val >> 12) & 0x3F];
        result += (i + 1 < SHA_DIGEST_LENGTH) ? base64_chars[(val >> 6) & 0x3F] : '=';
        result += (i + 2 < SHA_DIGEST_LENGTH) ? base64_chars[val & 0x3F] : '=';
    }
    
    return result;
}

std::string WebSocketHandler::create_websocket_response(const std::string& websocket_key) {
    std::string accept_key = generate_websocket_accept(websocket_key);
    
    std::ostringstream response;
    response << "HTTP/1.1 101 Switching Protocols\r\n";
    response << "Upgrade: websocket\r\n";
    response << "Connection: Upgrade\r\n";
    response << "Sec-WebSocket-Accept: " << accept_key << "\r\n";
    response << "\r\n";
    
    return response.str();
}

void WebSocketHandler::handle_websocket_connection(std::shared_ptr<tcp::socket> client_socket,
                                                 std::shared_ptr<tcp::socket> backend_socket) {
    // Start bidirectional relay
    relay_data(client_socket, backend_socket);
    relay_data(backend_socket, client_socket);
}

void WebSocketHandler::handle_websocket_ssl_connection(std::shared_ptr<asio::ssl::stream<tcp::socket>> client_socket,
                                                     std::shared_ptr<tcp::socket> backend_socket) {
    // Start bidirectional relay for SSL
    relay_ssl_data(client_socket, backend_socket);
    // For simplicity, we'll create a new socket using the executor
    auto executor = backend_socket->get_executor();
    auto plain_client = std::make_shared<tcp::socket>(executor);
    relay_data(backend_socket, plain_client);
}

void WebSocketHandler::relay_data(std::shared_ptr<tcp::socket> from, std::shared_ptr<tcp::socket> to) {
    auto buffer = std::make_shared<std::array<char, 8192>>();
    
    from->async_read_some(asio::buffer(*buffer),
        [this, from, to, buffer](std::error_code ec, std::size_t bytes_transferred) {
            if (!ec && bytes_transferred > 0) {
                asio::async_write(*to, asio::buffer(*buffer, bytes_transferred),
                    [this, from, to](std::error_code write_ec, std::size_t) {
                        if (!write_ec) {
                            relay_data(from, to);
                        }
                    });
            }
        });
}

void WebSocketHandler::relay_ssl_data(std::shared_ptr<asio::ssl::stream<tcp::socket>> from,
                                    std::shared_ptr<tcp::socket> to) {
    auto buffer = std::make_shared<std::array<char, 8192>>();
    
    from->async_read_some(asio::buffer(*buffer),
        [this, from, to, buffer](std::error_code ec, std::size_t bytes_transferred) {
            if (!ec && bytes_transferred > 0) {
                asio::async_write(*to, asio::buffer(*buffer, bytes_transferred),
                    [this, from, to](std::error_code write_ec, std::size_t) {
                        if (!write_ec) {
                            relay_ssl_data(from, to);
                        }
                    });
            }
        });
}