#include "server.hpp"
#include "request_handler.hpp"
#include "logging.hpp"
#include <iostream>
#include <regex>
#include <boost/asio/ip/address.hpp>

namespace jaseur {

Server::Server(const std::string& address, unsigned short port, 
              std::shared_ptr<RequestHandler> handler,
              const std::vector<std::string>& allowed_addresses,
              const std::vector<std::string>& blocked_addresses)
    : acceptor_(io_context_), 
      handler_(handler),
      allowed_addresses_(allowed_addresses),
      blocked_addresses_(blocked_addresses) {
    
    boost::asio::ip::tcp::endpoint endpoint{
        boost::asio::ip::make_address(address), 
        port
    };
    
    acceptor_.open(endpoint.protocol());
    acceptor_.set_option(boost::asio::socket_base::reuse_address(true));
    acceptor_.bind(endpoint);
    acceptor_.listen();
}

void Server::run() {
    running_ = true;
    accept();
    io_context_.run();
}

void Server::stop() {
    running_ = false;
    io_context_.stop();
}

void Server::accept() {
    if (!running_) return;
    
    acceptor_.async_accept(
        [this](boost::system::error_code ec, boost::asio::ip::tcp::socket socket) {
            if (!ec) {
                std::make_shared<Session>(std::move(socket), handler_, allowed_addresses_, blocked_addresses_)->start();
            }
            accept();
        });
}

void Session::start() {
    read_request();
}

void Session::read_request() {
    auto self = shared_from_this();
    
    http::async_read(
        socket_,
        buffer_,
        request_,
        [self](boost::system::error_code, std::size_t) {
            self->handle_request();
        });
}

std::string Session::get_client_ip(const http::request<http::string_body>& req) const {
    // Check X-Forwarded-For header first
    auto fwd_header = req.find("X-Forwarded-For");
    if (fwd_header != req.end()) {
        std::string forwarded_ips(fwd_header->value().data(), fwd_header->value().size());
        // Get the first IP in the list (original client)
        size_t pos = forwarded_ips.find(',');
        if (pos != std::string::npos) {
            return forwarded_ips.substr(0, pos);
        }
        return forwarded_ips;
    }
    
    // Fall back to direct connection IP
    return socket_.remote_endpoint().address().to_string();
}

bool Session::is_private_address(const std::string& ip) const {
    try {
        auto addr = boost::asio::ip::make_address(ip);
        
        if (addr.is_v4()) {
            auto v4_addr = addr.to_v4();
            auto bytes = v4_addr.to_bytes();
            
            // Check 10.0.0.0/8
            if (bytes[0] == 10) {
                return true;
            }
            
            // Check 172.16.0.0/12
            if (bytes[0] == 172 && (bytes[1] >= 16 && bytes[1] <= 31)) {
                return true;
            }
            
            // Check 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168) {
                return true;
            }
            
            // Check localhost
            if (bytes[0] == 127) {
                return true;
            }
            
        } else if (addr.is_v6()) {
            auto v6_addr = addr.to_v6();
            
            // Check if it's a private IPv6 address (fc00::/7)
            auto bytes = v6_addr.to_bytes();
            if ((bytes[0] & 0xfe) == 0xfc) {
                return true;
            }
            
            // Check if it's localhost
            if (v6_addr.is_loopback()) {
                return true;
            }
        }
    } catch (const std::exception& e) {
        Logger::get().warn("Failed to parse IP address {}: {}", ip, e.what());
        return false;
    }
    
    return false;
}

bool Session::matches_cidr_or_domain(const std::string& ip, const std::string& cidr_or_domain) const {
    try {
        // First check if the pattern is an IP address or CIDR notation
        if (cidr_or_domain.find('/') != std::string::npos || 
            cidr_or_domain.find_first_not_of("0123456789.:") == std::string::npos) {
            // It's an IP or CIDR
            auto client_addr = boost::asio::ip::make_address(ip);
            
            // If it's a CIDR notation, check subnet
            if (cidr_or_domain.find('/') != std::string::npos) {
                return is_in_subnet(client_addr, cidr_or_domain);
            } else {
                // It's a single IP comparison
                auto pattern_addr = boost::asio::ip::make_address(cidr_or_domain);
                return client_addr == pattern_addr;
            }
        } else {
            // It's a domain name, try to resolve it
            boost::asio::io_context io_context;
            boost::asio::ip::tcp::resolver resolver(io_context);
            
            // Perform synchronous resolution
            boost::system::error_code ec;
            auto results = resolver.resolve(cidr_or_domain, "", ec);
            
            if (ec) {
                Logger::get().warn("Failed to resolve domain {}: {}", cidr_or_domain, ec.message());
                return false;
            }
            
            // Create an IP address from the client IP
            auto client_addr = boost::asio::ip::make_address(ip);
            
            // Check if any of the resolved IPs match
            for (const auto& result : results) {
                auto endpoint = result.endpoint();
                auto resolved_addr = endpoint.address();
                
                if (client_addr == resolved_addr) {
                    return true;
                }
            }
        }
    } catch (const std::exception& e) {
        Logger::get().warn("Error matching IP {} against pattern {}: {}", ip, cidr_or_domain, e.what());
    }
    
    return false;
}

bool Session::is_in_subnet(const boost::asio::ip::address& ip, const std::string& subnet) const {
    try {
        // Parse CIDR notation (e.g., "192.168.1.0/24")
        size_t pos = subnet.find('/');
        if (pos == std::string::npos) {
            // Not CIDR notation, do a direct IP comparison
            return ip == boost::asio::ip::make_address(subnet);
        }
        
        std::string subnet_ip = subnet.substr(0, pos);
        int prefix_len = std::stoi(subnet.substr(pos + 1));
        
        // Handle IPv4
        if (ip.is_v4() && boost::asio::ip::make_address(subnet_ip).is_v4()) {
            auto ip_v4 = ip.to_v4();
            auto subnet_addr = boost::asio::ip::make_address(subnet_ip).to_v4();
            
            // Create mask from prefix length (using host byte order)
            uint32_t mask = 0;
            if (prefix_len > 0) {
                mask = 0xFFFFFFFF << (32 - prefix_len);
            }
            
            // Convert to host byte order integers for comparison
            uint32_t ip_int = ip_v4.to_uint();
            uint32_t subnet_int = subnet_addr.to_uint();
            
            // Apply mask and compare
            return (ip_int & mask) == (subnet_int & mask);
        } 
        // Handle IPv6
        else if (ip.is_v6() && boost::asio::ip::make_address(subnet_ip).is_v6()) {
            auto ip_v6 = ip.to_v6();
            auto subnet_addr = boost::asio::ip::make_address(subnet_ip).to_v6();
            
            // Get raw bytes
            auto ip_bytes = ip_v6.to_bytes();
            auto subnet_bytes = subnet_addr.to_bytes();
            
            // Compare byte by byte with mask
            int bytes_to_check = prefix_len / 8;
            int bits_remainder = prefix_len % 8;
            
            // Check full bytes
            for (int i = 0; i < bytes_to_check; i++) {
                if (ip_bytes[i] != subnet_bytes[i]) {
                    Logger::get().debug("IPv6 subnet check: {} in {}? Result: false (byte mismatch at pos {})", 
                        ip.to_string(), subnet, i);
                    return false;
                }
            }
            
            // Check remaining bits in the last byte
            if (bits_remainder > 0 && bytes_to_check < 16) {
                // Create a mask for the remaining bits
                uint8_t mask = ~(uint8_t(0xFF) >> bits_remainder);
                bool result = (ip_bytes[bytes_to_check] & mask) == (subnet_bytes[bytes_to_check] & mask);
                Logger::get().debug("IPv6 subnet check: {} in {}? Result: {} (partial byte check)", 
                    ip.to_string(), subnet, result ? "true" : "false");
                return result;
            }
            
            Logger::get().debug("IPv6 subnet check: {} in {}? Result: true", ip.to_string(), subnet);
            return true;
        }
    } catch (const std::exception& e) {
        Logger::get().warn("Error checking subnet match: {}", e.what());
    }
    
    return false;
}

bool Session::is_address_allowed(const http::request<http::string_body>& req) const {
    std::string client_ip = get_client_ip(req);
    
    // Check block list first (if any address matches, block the request)
    for (const auto& blocked : blocked_addresses_) {
        if (matches_cidr_or_domain(client_ip, blocked)) {
            Logger::get().debug("IP address {} blocked by rule {}", client_ip, blocked);
            return false;
        }
    }
    
    // If no allowed addresses are specified, only allow private addresses
    if (allowed_addresses_.empty()) {
        bool is_private = is_private_address(client_ip);
        if (!is_private) {
            Logger::get().debug("Rejected public IP address when only private addresses are allowed: {}", client_ip);
        }
        return is_private;
    }
    
    // Otherwise check against the explicit allow list
    for (const auto& allowed : allowed_addresses_) {
        if (matches_cidr_or_domain(client_ip, allowed)) {
            Logger::get().debug("IP address {} allowed by rule {}", client_ip, allowed);
            return true;
        }
    }
    
    Logger::get().debug("IP address {} not in allowed list", client_ip);
    return false;
}

void Session::handle_request() {
    if (!is_address_allowed(request_)) {
        Logger::get().warn("Request from unauthorized IP: {}", get_client_ip(request_));
        response_.version(request_.version());
        response_.result(http::status::forbidden);
        response_.set(http::field::server, fmt::format("{} {}", SERVER_NAME, VERSION));
        response_.set(http::field::content_type, "text/plain");
        response_.body() = "Access denied";
        response_.prepare_payload();
        
        auto self = shared_from_this();
        http::async_write(
            socket_,
            response_,
            [self](boost::system::error_code, std::size_t) {
                self->socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send);
            });
        return;
    }
    
    // Process the request normally
    try {
        auto result = handler_->handle_request(request_);
        response_ = std::move(result);
        response_.set(http::field::server, fmt::format("{} {}", SERVER_NAME, VERSION));
    } catch(const std::exception& e) {
        response_.version(request_.version());
        response_.result(http::status::internal_server_error);
        response_.set(http::field::server, fmt::format("{} {}", SERVER_NAME, VERSION));
        response_.set(http::field::content_type, "text/plain");
        response_.body() = std::string("Error: ") + e.what();
        response_.prepare_payload();
    }
    
    auto self = shared_from_this();
    http::async_write(
        socket_,
        response_,
        [self](boost::system::error_code, std::size_t) {
            self->socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send);
        });
}

} // namespace jaseur