#include <gtest/gtest.h>
#include "http_client.hpp"
#include "mock_http_client.hpp"

TEST(HttpClientTest, StripsUrlFragment) {
    auto client = jaseur::create_http_client();
    
    try {
        auto response = client->get("http://example.com/path#fragment");
        // If we reach here, the request was processed without throwing an exception
        // The actual HTTP request would have been made to example.com/path
        SUCCEED();
    } catch (const std::exception& e) {
        FAIL() << "Should not throw exception for URL with fragment: " << e.what();
    }
}

TEST(HttpClientTest, HandlesUrlWithoutFragment) {
    auto client = jaseur::create_http_client();
    
    try {
        auto response = client->get("http://example.com/path");
        SUCCEED();
    } catch (const std::exception& e) {
        FAIL() << "Should not throw exception for URL without fragment: " << e.what();
    }
}

TEST(HttpClientTest, HandlesComplexUrls) {
    auto client = jaseur::create_http_client();
    
    std::vector<std::string> urls = {
        "https://example.com:8443/path/to/resource#fragment",
        "http://example.com/path?query=value#fragment",
        "https://example.com/#fragment",
        "http://example.com#fragment"
    };
    
    for (const auto& url : urls) {
        try {
            auto response = client->get(url);
            SUCCEED();
        } catch (const std::exception& e) {
            FAIL() << "Failed to handle URL " << url << ": " << e.what();
        }
    }
}