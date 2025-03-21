#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "webfinger_handler.hpp"
#include "request_handler.hpp"
#include "resource_store.hpp"
#include "logging.hpp"
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
        Logger::init("debug");
        public_store_ = std::make_shared<::testing::NiceMock<MockResourceStore>>();
        handler_ = std::make_unique<WebFingerHandler>(public_store_, Config{});
    }
    
    http::request<http::string_body> create_webfinger_request(const std::string& resource) {
        http::request<http::string_body> req{http::verb::get, "/.well-known/webfinger?resource=" + resource, 11};
        req.set(http::field::host, "example.com");
        req.set(http::field::user_agent, "test");
        return req;
    }
    
    std::shared_ptr<MockResourceStore> public_store_;
    std::unique_ptr<WebFingerHandler> handler_;
    std::string test_account = "acct:test@example.com";
    std::string test_uri = "http://example.com/users/test";
};

TEST_F(WebFingerHandlerTest, HandlesWebFingerPath) {
    auto req = create_webfinger_request(test_account);
    EXPECT_TRUE(handler_->can_handle(req));
    
    req.target("/.well-known/other");
    EXPECT_FALSE(handler_->can_handle(req));
    
    // Test Accept header handling
    auto req_with_accept = create_webfinger_request(test_account);
    req_with_accept.set(http::field::accept, "application/jrd+json");
    EXPECT_TRUE(handler_->can_handle(req_with_accept));
    
    auto req_wrong_accept = create_webfinger_request(test_account);
    req_wrong_accept.set(http::field::accept, "application/xml");
    EXPECT_TRUE(handler_->can_handle(req_wrong_accept));
}

TEST_F(WebFingerHandlerTest, ValidatesAcceptHeader) {
    ON_CALL(*public_store_, exists(::testing::_))
        .WillByDefault(::testing::Return(false));
    ON_CALL(*public_store_, query(::testing::_))
        .WillByDefault(::testing::Return(std::vector<nlohmann::json>{}));

    auto req = create_webfinger_request(test_account);
    req.set(http::field::accept, "application/xml");
    auto res = handler_->handle_request(req);
    EXPECT_EQ(res.result(), http::status::not_acceptable);
}

TEST_F(WebFingerHandlerTest, HandlesAlsoKnownAsInPublicStore) {
    std::string test_uri = "http://example.com/users/test";
    std::string alias_uri = "acct:test@example.com";
    nlohmann::json actor = {
        {"id", test_uri},
        {"inbox", test_uri + "/inbox"},
        {"type", "Person"},
        {"alsoKnownAs", nlohmann::json::array({alias_uri})}
    };
    
    Query expected_query;
    expected_query["@prefix"] = "";
    expected_query["alsoKnownAs"] = alias_uri;
    EXPECT_CALL(*public_store_, query(expected_query))
        .WillOnce(::testing::Return(std::vector<nlohmann::json>{actor}));
        
    auto req = create_webfinger_request(alias_uri);
    req.set(http::field::accept, "application/jrd+json");
    auto res = handler_->handle_request(req);
    EXPECT_EQ(res.result(), http::status::ok);
    
    nlohmann::json response = nlohmann::json::parse(res.body());
    EXPECT_EQ(response["subject"], alias_uri);
    EXPECT_EQ(response["links"].size(), 1);
    EXPECT_EQ(response["links"][0]["rel"], "self");
    EXPECT_EQ(response["links"][0]["type"], "application/activity+json");
    EXPECT_EQ(response["links"][0]["href"], test_uri);
}

TEST_F(WebFingerHandlerTest, ReturnsNotFoundWhenResourceNotFound) {
        
    ON_CALL(*public_store_, exists(test_account))
        .WillByDefault(::testing::Return(false));
    ON_CALL(*public_store_, exists(test_uri))
        .WillByDefault(::testing::Return(false));
    ON_CALL(*public_store_, query(::testing::_))
        .WillByDefault(::testing::Return(std::vector<nlohmann::json>{}));
        
    auto req = create_webfinger_request(test_account);
    auto res = handler_->handle_request(req);
    
    EXPECT_EQ(res.result(), http::status::not_found);
}

TEST_F(WebFingerHandlerTest, HandlesMalformedRequest) {
    http::request<http::string_body> req{http::verb::get, "/.well-known/webfinger", 11};
    auto res = handler_->handle_request(req);
    EXPECT_EQ(res.result(), http::status::bad_request);
    
    req.target("/.well-known/webfinger?resource=");
    res = handler_->handle_request(req);
    EXPECT_EQ(res.result(), http::status::bad_request);
}