#pragma once

#include <boost/asio.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <memory>
#include <string>
#include <vector>
#include "config.hpp"

namespace http = boost::beast::http;

namespace jaseur {

class RequestHandler;

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(boost::asio::ip::tcp::socket socket,
           std::shared_ptr<RequestHandler> handler,
           const std::vector<std::string>& allowed_addresses,
           const std::vector<std::string>& blocked_addresses)
        : socket_(std::move(socket))
        , handler_(handler)
        , allowed_addresses_(allowed_addresses)
        , blocked_addresses_(blocked_addresses) {}

    void start();

private:
    void read_request();
    void handle_request();
    std::string get_client_ip(const http::request<http::string_body>& req) const;
    bool is_private_address(const std::string& ip) const;
    bool matches_cidr_or_domain(const std::string& ip, const std::string& cidr_or_domain) const;
    bool is_in_subnet(const boost::asio::ip::address& ip, const std::string& subnet) const;
    bool is_address_allowed(const http::request<http::string_body>& req) const;

    boost::asio::ip::tcp::socket socket_;
    boost::beast::flat_buffer buffer_;
    http::request<http::string_body> request_;
    http::response<http::string_body> response_;
    std::shared_ptr<RequestHandler> handler_;
    const std::vector<std::string>& allowed_addresses_;
    const std::vector<std::string>& blocked_addresses_;
};

class Server {
public:
    Server(const std::string& address, unsigned short port, 
           std::shared_ptr<RequestHandler> handler,
           const std::vector<std::string>& allowed_addresses = {},
           const std::vector<std::string>& blocked_addresses = {});
    
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;
    void run();
    void stop();
private:
    void accept();
    boost::asio::io_context io_context_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::shared_ptr<RequestHandler> handler_;
    std::vector<std::string> allowed_addresses_;
    std::vector<std::string> blocked_addresses_;
    bool running_ = false;
};
} // namespace jaseur