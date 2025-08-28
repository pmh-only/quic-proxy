#include <iostream>
#include <memory>
#include <thread>
#include <vector>
#include <cstdlib>
#include "proxy_server.h"
#include "config.h"

int main() {
    try {
        Config config;
        config.load_from_env();
        
        ProxyServer server(config);
        
        std::cout << "Starting reverse proxy server..." << std::endl;
        std::cout << "Backend: " << config.backend_host << ":" << config.backend_port << std::endl;
        std::cout << "Listening on ports 80 and 443" << std::endl;
        
        server.start();
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}