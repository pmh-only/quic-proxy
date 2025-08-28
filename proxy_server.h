#pragma once
#include <memory>
#include <thread>
#include <vector>
#include <asio.hpp>
#include <asio/ssl.hpp>
#include "config.h"
#include "tls_handler.h"
#include "http_handler.h"

using asio::ip::tcp;

class ProxyServer {
public:
    explicit ProxyServer(const Config& config);
    void start();
    void stop();

private:
    void start_http_server();
    void start_https_server();
    void accept_http_connections();
    void accept_https_connections();
    
    Config config_;
    asio::io_context io_context_;
    std::unique_ptr<tcp::acceptor> http_acceptor_;
    std::unique_ptr<tcp::acceptor> https_acceptor_;
    std::unique_ptr<asio::ssl::context> ssl_context_;
    std::unique_ptr<TLSHandler> tls_handler_;
    std::unique_ptr<HTTPHandler> http_handler_;
    std::vector<std::thread> worker_threads_;
    bool running_;
};