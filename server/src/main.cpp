#include "hal/remote_process.hpp"
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

namespace {

std::atomic<bool> g_stop_requested{false};

void handle_signal(int) {
    g_stop_requested.store(true);
}

void print_usage() {
    std::cout << "nce_server - New Cheat Engine Remote Target Server (NCE2)\n"
              << "Usage: nce_server [--host <bind_ip>] [--port <port>] [--token <secret>] [--help]\n"
              << "  --host   Bind address (default: 127.0.0.1)\n"
              << "  --port   TCP port     (default: 27055)\n"
              << "  --token  Optional shared secret token for client authentication\n";
}

} // namespace

int main(int argc, char** argv) {
    std::string host = "127.0.0.1";
    uint16_t port = 27055;
    std::string token;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_usage();
            return 0;
        }
        if (arg == "--host" && i + 1 < argc) {
            host = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            const int p = std::atoi(argv[++i]);
            if (p < 0 || p > 65535) {
                std::cerr << "Invalid port number.\n";
                return 1;
            }
            port = static_cast<uint16_t>(p);
        } else if (arg == "--token" && i + 1 < argc) {
            token = argv[++i];
        } else {
            std::cerr << "Unknown or incomplete option: " << arg << "\n";
            print_usage();
            return 1;
        }
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    nce::hal::RemoteServer server;
    if (!server.start(host, port, token)) {
        std::cerr << "Failed to start nce_server: " << server.last_error() << "\n";
        return 1;
    }

    std::cout << "nce_server listening on " << host << ":" << server.bound_port()
              << (token.empty() ? " (open)" : " (token-protected)") << std::endl;

    while (!g_stop_requested.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::cout << "\nShutting down nce_server..." << std::endl;
    server.stop();
    return 0;
}
