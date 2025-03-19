#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "resource_handler.hpp"
#include "resource_store.hpp"
#include <boost/beast/http.hpp>
#include <boost/beast/core.hpp>
#include <filesystem>
#include <fstream>
#include <string>
#include <memory>

using namespace jaseur;
namespace beast = boost::beast;
namespace http = beast::http;

// Create a mock class for the ResourceStore interface
class MockResourceStore : public ResourceStore {
public:
    MOCK_METHOD(bool, exists, (const std::string&), (override));
    MOCK_METHOD(nlohmann::json, get, (const std::string&), (override));
    MOCK_METHOD(bool, put, (const nlohmann::json&), (override));
    MOCK_METHOD(bool, remove, (const std::string&), (override));
    MOCK_METHOD((std::vector<nlohmann::json>), query, (const Query&), (override));
    MOCK_METHOD((std::unique_ptr<ResourceStore>), share, (), (override));
};

// Mock class for testing with controlled input/output
class ResourceHandlerTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_dir_ = "test_data";
        // Remove any existing test directory
        std::filesystem::remove_all(test_dir_);
        // Create a fresh test directory
        std::filesystem::create_directories(test_dir_);
        // Initialize the file store with the test directory
        file_store_ = std::make_shared<FileResourceStore>(test_dir_);
        handler_ = std::make_unique<ResourceHandler>(file_store_);
    }
    
    void TearDown() override {
        std::filesystem::remove_all(test_dir_);
    }
    
    http::request<http::string_body> create_get_request(const std::string& path, const std::string& domain = "server.test") {
        http::request<http::string_body> req{http::verb::get, path, 11};
        req.set(http::field::host, domain);
        req.set(http::field::user_agent, "test");
        return req;
    }
    
    std::string test_dir_;
    std::shared_ptr<ResourceStore> file_store_;
    std::unique_ptr<ResourceHandler> handler_;
};

TEST_F(ResourceHandlerTest, HandlesAnyResourcePath) {
    // Test various types of paths
    std::vector<std::string> test_paths = {
        "/users/testuser",
        "/any/arbitrary/path",
        "/custom/resource",
        "/",
        "/single"
    };
    
    for (const auto& path : test_paths) {
        std::string domain = "server.test";
        std::string resource_uri = "http://" + domain + path;
        
        // Create test resource JSON
        nlohmann::json resource_json = {
            {"@context", "https://www.w3.org/ns/activitystreams"},
            {"id", resource_uri},
            {"type", "Object"},
            {"name", "Test Resource"}
        };
        
        // Add the resource to our store
        ASSERT_TRUE(file_store_->put(resource_json));
        
        // Create a GET request to the resource path
        auto req = create_get_request(path, domain);
        auto res = handler_->handle_request(req);
        
        // Validate the response
        EXPECT_EQ(res.result(), http::status::ok) << "Failed for path: " << path;
        EXPECT_EQ(res[http::field::content_type], "application/activity+json") << "Failed for path: " << path;
        
        // Parse and validate the body
        nlohmann::json retrieved = nlohmann::json::parse(res.body());
        EXPECT_EQ(retrieved["id"], resource_uri) << "Failed for path: " << path;
    }
}

TEST_F(ResourceHandlerTest, HandleNonExistentResource) {
    std::string path = "/non/existent/path";
    auto req = create_get_request(path);
    auto res = handler_->handle_request(req);
    
    // Response should be 404 Not Found
    EXPECT_EQ(res.result(), http::status::not_found);
}

TEST_F(ResourceHandlerTest, MockResourceStore) {
    auto mock_store = std::make_shared<::testing::NiceMock<MockResourceStore>>();
    
    std::string path = "/any/arbitrary/path";
    std::string domain = "server.test";
    std::string test_uri = "http://" + domain + path;
    
    nlohmann::json test_resource = {
        {"id", test_uri},
        {"type", "Object"},
        {"name", "Test Resource"}
    };
    
    // Configure mock expectations
    EXPECT_CALL(*mock_store, exists(test_uri))
        .WillOnce(::testing::Return(true));
    
    EXPECT_CALL(*mock_store, get(test_uri))
        .WillOnce(::testing::Return(test_resource));
    
    auto mock_handler = std::make_unique<ResourceHandler>(mock_store);
    
    auto req = create_get_request(path, domain);
    auto res = mock_handler->handle_request(req);
    
    EXPECT_EQ(res.result(), http::status::ok);
    EXPECT_EQ(res[http::field::content_type], "application/activity+json");
    
    nlohmann::json retrieved = nlohmann::json::parse(res.body());
    EXPECT_EQ(retrieved["id"], test_uri);
    EXPECT_EQ(retrieved["name"], "Test Resource");
}