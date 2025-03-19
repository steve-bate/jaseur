#pragma once

#include "http_client.hpp"
#include <map>
#include <string>
#include <functional>

namespace jaseur {
namespace test {

// Mock HTTP client for testing
class MockHttpClient : public HttpClient {
public:
    using HttpHandler = std::function<Response(const std::string&, const std::map<std::string, std::string>&)>;
    using PostHandler = std::function<Response(const std::string&, const std::string&, const std::map<std::string, std::string>&)>;
    
    MockHttpClient() {
        // Default handlers return 404
        get_handler_ = [](const std::string&, const std::map<std::string, std::string>&) {
            return Response{404, {}, "Not Found"};
        };
        
        post_handler_ = [](const std::string&, const std::string&, const std::map<std::string, std::string>&) {
            return Response{404, {}, "Not Found"};
        };
    }
    
    // Set a handler for GET requests
    void set_get_handler(HttpHandler handler) {
        get_handler_ = std::move(handler);
    }
    
    // Set a handler for POST requests
    void set_post_handler(PostHandler handler) {
        post_handler_ = std::move(handler);
    }
    
    // Implement the HttpClient interface
    Response get(const std::string& url, const std::map<std::string, std::string>& headers = {}) override {
        // Record the request
        last_get_url_ = url;
        last_get_headers_ = headers;
        
        // Call the handler
        return get_handler_(url, headers);
    }
    
    Response post(const std::string& url, const std::string& body, const std::map<std::string, std::string>& headers = {}) override {
        // Record the request
        last_post_url_ = url;
        last_post_body_ = body;
        last_post_headers_ = headers;
        
        // Call the handler
        return post_handler_(url, body, headers);
    }
    
    // Access the last request details
    const std::string& last_get_url() const { return last_get_url_; }
    const std::map<std::string, std::string>& last_get_headers() const { return last_get_headers_; }
    
    const std::string& last_post_url() const { return last_post_url_; }
    const std::string& last_post_body() const { return last_post_body_; }
    const std::map<std::string, std::string>& last_post_headers() const { return last_post_headers_; }
    
private:
    HttpHandler get_handler_;
    PostHandler post_handler_;
    
    std::string last_get_url_;
    std::map<std::string, std::string> last_get_headers_;
    
    std::string last_post_url_;
    std::string last_post_body_;
    std::map<std::string, std::string> last_post_headers_;
};

} // namespace test
} // namespace jaseur