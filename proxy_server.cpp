#include "proxy_server.h"
#include <iostream>
#include <asio/ssl.hpp>

ProxyServer::ProxyServer(const Config& config) 
    : config_(config), running_(false) {
    
    ssl_context_ = std::make_unique<asio::ssl::context>(asio::ssl::context::tlsv12_server);
    tls_handler_ = std::make_unique<TLSHandler>(*ssl_context_, config_);
    http_handler_ = std::make_unique<HTTPHandler>(config_);
    
    // Initialize HTTP/3 handler if supported
    try {
        http3_handler_ = std::make_unique<HTTP3Handler>(config_, io_context_);
        if (!http3_handler_->is_http3_supported()) {
            std::cout << "HTTP/3 not supported, will use HTTP/2 only" << std::endl;
            http3_handler_.reset();
        }
    } catch (const std::exception& e) {
        std::cerr << "HTTP/3 initialization failed: " << e.what() << std::endl;
        http3_handler_.reset();
    }
    
    tls_handler_->configure_ssl_context();
}

void ProxyServer::start() {
    running_ = true;
    
    start_http_server();
    start_https_server();
    
    // Start HTTP/3 server if available
    if (http3_handler_) {
        start_http3_server();
    }
    
    // Create worker threads
    const size_t num_threads = std::thread::hardware_concurrency();
    worker_threads_.reserve(num_threads);
    
    for (size_t i = 0; i < num_threads; ++i) {
        worker_threads_.emplace_back([this]() {
            io_context_.run();
        });
    }
    
    // Wait for all threads
    for (auto& thread : worker_threads_) {
        thread.join();
    }
}

void ProxyServer::stop() {
    running_ = false;
    
    // Stop HTTP/3 handler if running
    if (http3_handler_) {
        http3_handler_->stop();
    }
    
    io_context_.stop();
}

void ProxyServer::start_http_server() {
    http_acceptor_ = std::make_unique<tcp::acceptor>(
        io_context_, 
        tcp::endpoint(tcp::v4(), config_.http_port)
    );
    
    accept_http_connections();
}

void ProxyServer::start_https_server() {
    https_acceptor_ = std::make_unique<tcp::acceptor>(
        io_context_, 
        tcp::endpoint(tcp::v4(), config_.https_port)
    );
    
    accept_https_connections();
}

void ProxyServer::accept_http_connections() {
    auto socket = std::make_shared<tcp::socket>(io_context_);
    
    http_acceptor_->async_accept(*socket,
        [this, socket](std::error_code ec) {
            if (!ec && running_) {
                http_handler_->handle_http_connection(socket);
            }
            
            if (running_) {
                accept_http_connections();
            }
        });
}

void ProxyServer::accept_https_connections() {
    auto ssl_socket = std::make_shared<asio::ssl::stream<tcp::socket>>(
        io_context_, *ssl_context_
    );
    
    https_acceptor_->async_accept(ssl_socket->lowest_layer(),
        [this, ssl_socket](std::error_code ec) {
            if (!ec && running_) {
                http_handler_->handle_https_connection(ssl_socket);
            }
            
            if (running_) {
                accept_https_connections();
            }
        });
}

void ProxyServer::start_http3_server() {
    try {
        http3_handler_->start_quic_server();
        std::cout << "HTTP/3 QUIC server started successfully" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Failed to start HTTP/3 server: " << e.what() << std::endl;
        http3_handler_.reset();
    }
}