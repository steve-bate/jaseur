#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "webfinger_handler.hpp"
#include "request_handler.hpp"
#include "resource_store.hpp"
#include <boost/beast/http.hpp>
#include <boost/beast/core.hpp>
#include <filesystem>
#include <fstream>
#include <memory>
#include <nlohmann/json.hpp>

using namespace jaseur;
namespace beast = boost::beast;
namespace http = beast::http;

// Reuse MockResourceStore from the ActivityPubHandler tests if needed
class MockResourceStore : public ResourceStore {
public:
    MOCK_METHOD(nlohmann::json, get, (const std::string& uri), (override));
    MOCK_METHOD(bool, exists, (const std::string& uri), (override));
    MOCK_METHOD(bool, put, (const nlohmann::json& json), (override));
    MOCK_METHOD(bool, remove, (const std::string& uri), (override));
    MOCK_METHOD(std::vector<nlohmann::json>, query, (const Query& query), (override));
    MOCK_METHOD((std::unique_ptr<ResourceStore>), share, (), (override));
};

class WebFingerHandlerTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_dir_ = "test_ap_data";
        file_store_ = std::make_unique<FileResourceStore>(test_dir_);
        
        if (!std::filesystem::exists(test_dir_)) {
            std::filesystem::create_directory(test_dir_);
        }
        // Create handler with our test file store and store both as concrete and interface type
        auto handler = std::make_unique<WebFingerHandler>(std::move(file_store_), jaseur::Config{});
        concrete_handler_ = handler.get();  // Keep a raw pointer to the concrete type for tests that need it
        handler_ = std::move(handler);      // Store as RequestHandler interface type
        
        // Create a new file store for test helpers
        file_store_ = std::make_unique<FileResourceStore>(test_dir_);
    }

    void TearDown() override {
        if (std::filesystem::exists(test_dir_)) {
            std::filesystem::remove_all(test_dir_);
        }
    }

    // Helper to create test actor JSON file
    void create_test_actor(const std::string& uri, bool has_inbox = true) {
        nlohmann::json actor = {
            {"type", "Person"},
            {"id", uri}
        };
        if (has_inbox) {
            actor["inbox"] = uri + "/inbox";
        }
        file_store_->put(actor);
    }

    // Helper to create HTTP GET request
    http::request<http::string_body> create_get_request(const std::string& target) {
        http::request<http::string_body> req{http::verb::get, target, 11};
        req.set(http::field::host, "server.test");
        req.set(http::field::user_agent, "WebFingerTest");
        return req;
    }

    std::string test_dir_;
    std::unique_ptr<RequestHandler> handler_;      // Using interface pointer
    WebFingerHandler* concrete_handler_;           // Raw pointer for specific tests
    std::unique_ptr<ResourceStore> file_store_;
};

TEST_F(WebFingerHandlerTest, CanHandleMethodTest) {
    // Should handle the exact path
    EXPECT_TRUE(handler_->can_handle(create_get_request("/.well-known/webfinger")));

    // Should handle paths that start with /.well-known/webfinger
    EXPECT_TRUE(handler_->can_handle(create_get_request("/.well-known/webfinger?resource=acct:user@server.test")));

    // Should not handle other paths
    EXPECT_FALSE(handler_->can_handle(create_get_request("/users/bob")));
    EXPECT_FALSE(handler_->can_handle(create_get_request("/well-known/webfinger")));
    EXPECT_FALSE(handler_->can_handle(create_get_request("/.well-known/host-meta")));
    EXPECT_FALSE(handler_->can_handle(create_get_request("/other/.well-known/webfinger")));
    EXPECT_FALSE(handler_->can_handle(create_get_request("")));
}

TEST_F(WebFingerHandlerTest, HandlesInvalidResourceURI) {
    auto req = create_get_request("/.well-known/webfinger?resource=not-a-uri");
    auto res = handler_->handle_request(req);
    EXPECT_EQ(res.result(), http::status::bad_request);
    nlohmann::json response = nlohmann::json::parse(res.body());
    EXPECT_TRUE(response["error"].get<std::string>().find("Invalid") != std::string::npos);
}

TEST_F(WebFingerHandlerTest, HandlesActorResource) {
    std::string actor_uri = "https://server.test/users/test";
    create_test_actor(actor_uri);
    auto req = create_get_request("/.well-known/webfinger?resource=" + actor_uri);
    auto res = handler_->handle_request(req);
    EXPECT_EQ(res.result(), http::status::ok);
    EXPECT_EQ(res[http::field::content_type], "application/jrd+json");
    nlohmann::json response = nlohmann::json::parse(res.body());
    EXPECT_EQ(response["subject"], actor_uri);
    EXPECT_FALSE(response["links"].empty());
    auto self_link = response["links"][0];
    EXPECT_EQ(self_link["rel"], "self");
    EXPECT_EQ(self_link["type"], "application/activity+json");
    EXPECT_EQ(self_link["href"], actor_uri);
}

TEST_F(WebFingerHandlerTest, HandlesNonActorResource) {
    std::string resource_uri = "https://server.test/resource";
    create_test_actor(resource_uri, false);  // Create without inbox
    auto req = create_get_request("/.well-known/webfinger?resource=" + resource_uri);
    auto res = handler_->handle_request(req);
    EXPECT_EQ(res.result(), http::status::ok);
    nlohmann::json response = nlohmann::json::parse(res.body());
    EXPECT_EQ(response["subject"], resource_uri);
    EXPECT_TRUE(response["links"].empty());
}

TEST_F(WebFingerHandlerTest, HandlesNonexistentResource) {
    std::string resource_uri = "https://server.test/nonexistent";
    auto req = create_get_request("/.well-known/webfinger?resource=" + resource_uri);
    auto res = handler_->handle_request(req);
    EXPECT_EQ(res.result(), http::status::ok);
    nlohmann::json response = nlohmann::json::parse(res.body());
    EXPECT_EQ(response["subject"], resource_uri);
    EXPECT_TRUE(response["links"].empty());
}

TEST_F(WebFingerHandlerTest, HandlesAcctURI) {
    std::string acct_uri = "acct:test@server.test";
    std::string actor_uri = "https://server.test/users/test";
    
    // Create an actor that has the acct URI in alsoKnownAs
    nlohmann::json actor = {
        {"type", "Person"},
        {"id", actor_uri},
        {"inbox", actor_uri + "/inbox"},
        {"alsoKnownAs", acct_uri}
    };
    file_store_->put(actor);

    auto req = create_get_request("/.well-known/webfinger?resource=" + acct_uri);
    auto res = handler_->handle_request(req);
    
    EXPECT_EQ(res.result(), http::status::ok);
    EXPECT_EQ(res[http::field::content_type], "application/jrd+json");
    
    nlohmann::json response = nlohmann::json::parse(res.body());
    EXPECT_EQ(response["subject"], acct_uri);
    EXPECT_FALSE(response["links"].empty());
    
    auto self_link = response["links"][0];
    EXPECT_EQ(self_link["rel"], "self");
    EXPECT_EQ(self_link["type"], "application/activity+json");
    EXPECT_EQ(self_link["href"], actor_uri);
}

TEST_F(WebFingerHandlerTest, MockResourceStore) {
    auto mock_store = std::make_unique<::testing::NiceMock<MockResourceStore>>();
    std::string resource_uri = "https://server.test/users/mocktest";
    
    // Set up mock expectations
    EXPECT_CALL(*mock_store, exists(resource_uri))
        .WillOnce(::testing::Return(true));
    
    nlohmann::json actor_data = {
        {"id", resource_uri},
        {"type", "Person"},
        {"inbox", resource_uri + "/inbox"}
    };
    
    EXPECT_CALL(*mock_store, get(resource_uri))
        .WillOnce(::testing::Return(actor_data));
    
    // Create handler with mock store and access through interface
    std::unique_ptr<RequestHandler> mock_handler = 
        std::make_unique<WebFingerHandler>(std::move(mock_store), jaseur::Config{});
    
    auto req = create_get_request("/.well-known/webfinger?resource=" + resource_uri);
    auto res = mock_handler->handle_request(req);
    
    EXPECT_EQ(res.result(), http::status::ok);
    nlohmann::json response = nlohmann::json::parse(res.body());
    EXPECT_FALSE(response["links"].empty());
}