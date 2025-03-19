#pragma once
#include <string>
#include <map>
#include <memory>

namespace jaseur {
/**
 * Interface for making HTTP requests
 */
class HttpClient {
public:
    virtual ~HttpClient() = default;
    
    struct Response {
        int status_code;
        std::map<std::string, std::string> headers;
        std::string body;
    };
    
    /**
     * Send an HTTP GET request
     * 
     * @param url The URL to send the request to
     * @param headers Additional headers to include in the request
     * @return The HTTP response
     */
    virtual Response get(
        const std::string& url,
        const std::map<std::string, std::string>& headers = {}) = 0;
    
    /**
     * Send an HTTP POST request
     * 
     * @param url The URL to send the request to
     * @param body The request body
     * @param headers Additional headers to include in the request
     * @return The HTTP response
     */
    virtual Response post(
        const std::string& url,
        const std::string& body,
        const std::map<std::string, std::string>& headers = {}) = 0;
};

// Factory function to create HttpClient instances
std::unique_ptr<HttpClient> create_http_client();

} // namespace jaseur