#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "server.hpp"
#include "request_handler.hpp"
#include "webfinger_handler.hpp"
#include "resource_handler.hpp"
#include "resource_store.hpp"
#include "logging.hpp"
#include <thread>
#include <chrono>
#include <boost/beast/http.hpp>
#include <boost/beast/core.hpp>
#include <boost/asio.hpp>

using namespace jaseur;
namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;

class MockRequestHandler : public RequestHandler {
public:
    MockRequestHandler() : RequestHandler(jaseur::Config{}) {}
    MOCK_METHOD(http::response<http::string_body>, handle_request_impl, (const http::request<http::string_body>&), (override));
    MOCK_METHOD(bool, can_handle, (const http::request<http::string_body>&), (const, override));
};

class ServerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize logger for tests
        Logger::init("info");
        
        // Use a test port and localhost for testing
        port_ = 45678;
        address_ = "127.0.0.1";
        
        // Create test data directory
        test_dir_ = "test_jaseur_data";
        if (!std::filesystem::exists(test_dir_)) {
            std::filesystem::create_directory(test_dir_);
        }
        
        // Create a shared FileResourceStore for the ResourceHandler
        auto file_store = std::make_shared<FileResourceStore>(test_dir_);
        
        // Create ResourceHandler with the shared store
        auto resource_handler = std::make_shared<ResourceHandler>(file_store, jaseur::Config{});
        
        // Create WebFingerHandler with a new store instance
        auto webfinger_handler = std::make_shared<WebFingerHandler>(
            std::make_unique<FileResourceStore>(test_dir_), jaseur::Config{});
        
        // Chain the handlers
        webfinger_handler->set_successor(resource_handler);
        handler_ = webfinger_handler;
        
        // Store file store pointer for test use
        file_store_ = file_store.get();
    }
    
    void TearDown() override {
        if (std::filesystem::exists(test_dir_)) {
            std::filesystem::remove_all(test_dir_);
        }
    }
    
    // Helper to send HTTP request and get response
    http::response<http::string_body> send_request(const http::request<http::string_body>& req) {
        net::io_context io_context;
        tcp::socket socket(io_context);
        socket.connect(tcp::endpoint(net::ip::make_address(address_), port_));
        
        // Set the Host header to match the server's address:port if not already set
        http::request<http::string_body> request = req;
        if (request.find(http::field::host) == request.end()) {
            request.set(http::field::host, address_ + ":" + std::to_string(port_));
        }
        
        http::write(socket, request);
        
        beast::flat_buffer buffer;
        http::response<http::string_body> res;
        http::read(socket, buffer, res);
        
        socket.close();
        return res;
    }
    
    unsigned short port_;
    std::string address_;
    std::string test_dir_;
    std::shared_ptr<RequestHandler> handler_;
    FileResourceStore* file_store_; // Non-owning pointer for test use
};

TEST_F(ServerTest, ServerInitialization) {
    ASSERT_NO_THROW({
        Server server(address_, port_, handler_);
    });
}

TEST_F(ServerTest, ServerStartStop) {
    Server server(address_, port_, handler_, {}, {});
    
    // Start server in a separate thread
    std::thread server_thread([&server]() {
        server.run();
    });
    
    // Give the server a moment to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Stop the server
    server.stop();
    
    // Wait for the server thread to finish
    server_thread.join();
}

TEST_F(ServerTest, ConnectionTest) {
    Server server(address_, port_, handler_, {}, {});
    
    // Start server in a separate thread
    std::thread server_thread([&server]() {
        server.run();
    });
    
    // Give the server a moment to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Create a client and try to connect
    net::io_context io_context;
    tcp::socket socket(io_context);
    
    ASSERT_NO_THROW({
        socket.connect(tcp::endpoint(net::ip::make_address(address_), port_));
    });
    
    // Clean up
    socket.close();
    server.stop();
    server_thread.join();
}

TEST_F(ServerTest, HTTPRequestTest) {
    auto mock_handler = std::make_shared<MockRequestHandler>();
    
    // Configure the mock to handle all requests but return Method Not Allowed
    EXPECT_CALL(*mock_handler, can_handle(testing::_))
        .WillRepeatedly(testing::Return(true));
    EXPECT_CALL(*mock_handler, handle_request_impl(testing::_))
        .WillRepeatedly([](const http::request<http::string_body>& req) {
            http::response<http::string_body> res{http::status::method_not_allowed, req.version()};
            res.set(http::field::server, fmt::format("{} {}", SERVER_NAME, VERSION));
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::allow, ""); // Empty allow header since no methods are allowed
            res.body() = "Method not allowed";
            return res;
        });
    
    Server server(address_, port_, mock_handler, {}, {});
    
    // Start server in a separate thread
    std::thread server_thread([&server]() {
        server.run();
    });
    
    // Give the server a moment to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Create a client and send an HTTP request
    net::io_context io_context;
    tcp::socket socket(io_context);
    socket.connect(tcp::endpoint(net::ip::make_address(address_), port_));
    
    // Prepare and send HTTP request
    http::request<http::string_body> req{http::verb::get, "/", 11};
    req.set(http::field::host, address_);
    req.set(http::field::user_agent, "ServerTest");
    http::write(socket, req);
    
    // Read the response
    beast::flat_buffer buffer;
    http::response<http::string_body> res;
    http::read(socket, buffer, res);
    
    // Verify response - server now returns Method Not Allowed for non-existent path
    EXPECT_EQ(res.result(), http::status::method_not_allowed);
    
    // Clean up
    socket.close();
    server.stop();
    server_thread.join();
}

TEST_F(ServerTest, MultipleConnectionsTest) {
    Server server(address_, port_, handler_, {}, {});
    
    // Start server in a separate thread
    std::thread server_thread([&server]() {
        server.run();
    });
    
    // Give the server a moment to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Test multiple concurrent connections
    const int NUM_CONNECTIONS = 5;
    std::vector<std::unique_ptr<tcp::socket>> sockets;
    net::io_context io_context;
    
    for (int i = 0; i < NUM_CONNECTIONS; ++i) {
        sockets.push_back(std::make_unique<tcp::socket>(io_context));
        ASSERT_NO_THROW({
            sockets[i]->connect(tcp::endpoint(net::ip::make_address(address_), port_));
        });
    }
    
    // Clean up
    for (auto& socket : sockets) {
        socket->close();
    }
    server.stop();
    server_thread.join();
}

TEST_F(ServerTest, RequestHandlerChain) {
    // Start server with our handler chain
    Server server(address_, port_, handler_, {}, {});
    
    // Start server in a separate thread
    std::thread server_thread([&server]() {
        server.run();
    });
    
    // Give the server a moment to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    try {
        // Create base URL for resources
        std::string base_url = "http://" + address_ + ":" + std::to_string(port_);
        std::string actor_uri = base_url + "/users/testuser";
        
        // Create test actor data with all required fields
        nlohmann::json actor = {
            {"@context", "https://www.w3.org/ns/activitystreams"},
            {"type", "Person"},
            {"id", actor_uri},
            {"inbox", base_url + "/users/testuser/inbox"},
            {"outbox", base_url + "/users/testuser/outbox"},
            {"following", base_url + "/users/testuser/following"},
            {"followers", base_url + "/users/testuser/followers"},
            {"preferredUsername", "testuser"},
            {"name", "Test User"},
            {"url", actor_uri}
        };
        
        // Store the actor using its full URI as the storage key
        ASSERT_TRUE(file_store_->put(actor));
        
        // Test WebFinger request
        http::request<http::string_body> webfinger_req{http::verb::get, 
            "/.well-known/webfinger?resource=acct:testuser@" + address_ + ":" + std::to_string(port_), 11};
        webfinger_req.set(http::field::host, address_ + ":" + std::to_string(port_));
        auto webfinger_res = send_request(webfinger_req);
        
        EXPECT_EQ(webfinger_res.result(), http::status::ok);
        EXPECT_EQ(webfinger_res.at("Content-Type"), "application/jrd+json");
        
        // Test ActivityPub request for the actor
        http::request<http::string_body> activitypub_req{http::verb::get, 
            "/users/testuser", 11};
        activitypub_req.set(http::field::host, address_ + ":" + std::to_string(port_));
        activitypub_req.set(http::field::accept, "application/activity+json");
        auto activitypub_res = send_request(activitypub_req);
        
        // Check the response status and content type
        EXPECT_EQ(activitypub_res.result(), http::status::ok);
        EXPECT_EQ(activitypub_res.at("Content-Type"), "application/activity+json");
        
        // Clean up
        server.stop();
        server_thread.join();
    }
    catch (...) {
        server.stop();
        server_thread.join();
        throw;
    }
}

TEST_F(ServerTest, ExplicitIPAllowList) {
    std::vector<std::string> allowed_addresses = {"127.0.0.1", "192.168.1.1"};
    std::vector<std::string> blocked_addresses = {};
    Server server(address_, port_, handler_, allowed_addresses, blocked_addresses);
    
    std::thread server_thread([&server]() {
        server.run();
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    try {
        // Test allowed IP (localhost)
        http::request<http::string_body> req{http::verb::get, "/", 11};
        req.set(http::field::host, address_);
        auto res = send_request(req);
        EXPECT_NE(res.result(), http::status::forbidden);
        
        // Test forwarded IP that's allowed
        http::request<http::string_body> req2{http::verb::get, "/", 11};
        req2.set(http::field::host, address_);
        req2.set("X-Forwarded-For", "192.168.1.1");
        auto res2 = send_request(req2);
        EXPECT_NE(res2.result(), http::status::forbidden);
        
        // Test forwarded IP that's not allowed
        http::request<http::string_body> req3{http::verb::get, "/", 11};
        req3.set(http::field::host, address_);
        req3.set("X-Forwarded-For", "1.2.3.4");
        auto res3 = send_request(req3);
        EXPECT_EQ(res3.result(), http::status::forbidden);
        
    } catch (...) {
        server.stop();
        server_thread.join();
        throw;
    }
    
    server.stop();
    server_thread.join();
}

TEST_F(ServerTest, DefaultPrivateNetworkAccess) {
    // Create server with no explicit IP allow list or blocklist
    Server server(address_, port_, handler_, {}, {});
    
    std::thread server_thread([&server]() {
        server.run();
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    try {
        // Test localhost (should be allowed)
        http::request<http::string_body> req{http::verb::get, "/", 11};
        req.set(http::field::host, address_);
        auto res = send_request(req);
        EXPECT_NE(res.result(), http::status::forbidden);
        
        // Test private network addresses via X-Forwarded-For
        std::vector<std::string> private_ips = {
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "fc00::1"
        };
        
        for (const auto& ip : private_ips) {
            http::request<http::string_body> req2{http::verb::get, "/", 11};
            req2.set(http::field::host, address_);
            req2.set("X-Forwarded-For", ip);
            auto res2 = send_request(req2);
            EXPECT_NE(res2.result(), http::status::forbidden) 
                << "Private IP " << ip << " should be allowed";
        }
        
        // Test public IP addresses (should be rejected)
        std::vector<std::string> public_ips = {
            "8.8.8.8",
            "203.0.113.1",
            "2001:db8::1"
        };
        
        for (const auto& ip : public_ips) {
            http::request<http::string_body> req3{http::verb::get, "/", 11};
            req3.set(http::field::host, address_);
            req3.set("X-Forwarded-For", ip);
            auto res3 = send_request(req3);
            EXPECT_EQ(res3.result(), http::status::forbidden)
                << "Public IP " << ip << " should be rejected";
        }
        
    } catch (...) {
        server.stop();
        server_thread.join();
        throw;
    }
    
    server.stop();
    server_thread.join();
}

TEST_F(ServerTest, XForwardedForHeaderParsing) {
    Server server(address_, port_, handler_, {}, {});
    
    std::thread server_thread([&server]() {
        server.run();
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    try {
        // Test chain of forwarded IPs - should use first one
        http::request<http::string_body> req{http::verb::get, "/", 11};
        req.set(http::field::host, address_);
        req.set("X-Forwarded-For", "8.8.8.8, 192.168.1.1, 10.0.0.1");
        auto res = send_request(req);
        EXPECT_EQ(res.result(), http::status::forbidden) 
            << "Should use first IP (8.8.8.8) which is public and should be rejected";
        
        // Test chain with private IP first
        http::request<http::string_body> req2{http::verb::get, "/", 11};
        req2.set(http::field::host, address_);
        req2.set("X-Forwarded-For", "192.168.1.1, 8.8.8.8, 10.0.0.1");
        auto res2 = send_request(req2);
        EXPECT_NE(res2.result(), http::status::forbidden)
            << "Should use first IP (192.168.1.1) which is private and should be allowed";
        
    } catch (...) {
        server.stop();
        server_thread.join();
        throw;
    }
    
    server.stop();
    server_thread.join();
}

TEST_F(ServerTest, BlockAddressTest) {
    // Set up a server with an allow list that includes 192.168.1.1
    // but a block list that specifically blocks it
    std::vector<std::string> allowed_addresses = {"127.0.0.1", "192.168.1.0/24"};
    std::vector<std::string> blocked_addresses = {"192.168.1.1"};
    
    Server server(address_, port_, handler_, allowed_addresses, blocked_addresses);
    
    std::thread server_thread([&server]() {
        server.run();
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    try {
        // Test localhost (should be allowed)
        http::request<http::string_body> req{http::verb::get, "/", 11};
        req.set(http::field::host, address_);
        auto res = send_request(req);
        EXPECT_NE(res.result(), http::status::forbidden);
        
        // Test IP in allowed subnet but specifically blocked
        http::request<http::string_body> req2{http::verb::get, "/", 11};
        req2.set(http::field::host, address_);
        req2.set("X-Forwarded-For", "192.168.1.1");
        auto res2 = send_request(req2);
        EXPECT_EQ(res2.result(), http::status::forbidden) 
            << "IP 192.168.1.1 should be blocked despite being in allowed subnet";
        
        // Test IP in allowed subnet and not blocked
        http::request<http::string_body> req3{http::verb::get, "/", 11};
        req3.set(http::field::host, address_);
        req3.set("X-Forwarded-For", "192.168.1.2");
        auto res3 = send_request(req3);
        EXPECT_NE(res3.result(), http::status::forbidden)
            << "IP 192.168.1.2 should be allowed";
        
    } catch (...) {
        server.stop();
        server_thread.join();
        throw;
    }
    
    server.stop();
    server_thread.join();
}