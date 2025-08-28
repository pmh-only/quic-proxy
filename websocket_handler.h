#pragma once
#include <memory>
#include <string>
#include <array>
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <openssl/sha.h>

using asio::ip::tcp;

class WebSocketHandler {
public:
    WebSocketHandler();
    
    std::string generate_websocket_accept(const std::string& websocket_key);
    std::string create_websocket_response(const std::string& websocket_key);
    
    void handle_websocket_connection(std::shared_ptr<tcp::socket> client_socket, 
                                   std::shared_ptr<tcp::socket> backend_socket);
    
    void handle_websocket_ssl_connection(std::shared_ptr<asio::ssl::stream<tcp::socket>> client_socket,
                                       std::shared_ptr<tcp::socket> backend_socket);

private:
    void relay_data(std::shared_ptr<tcp::socket> from, std::shared_ptr<tcp::socket> to);
    void relay_ssl_data(std::shared_ptr<asio::ssl::stream<tcp::socket>> from, 
                       std::shared_ptr<tcp::socket> to);
    
    static const std::string WEBSOCKET_MAGIC_STRING;
};