#ifndef WEBFINGER_HANDLER_TEST_HPP
#define WEBFINGER_HANDLER_TEST_HPP

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "webfinger_handler.hpp"
#include "request_handler.hpp"
#include "resource_store.hpp"
#include <boost/beast/http.hpp>
#include <memory>

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
        public_store_ = std::make_shared<::testing::NiceMock<MockResourceStore>>();
        private_store_ = std::make_shared<::testing::NiceMock<MockResourceStore>>();
        handler_ = std::make_unique<WebFingerHandler>(public_store_, private_store_, Config{});

        // Set up common test data
        test_domain = "example.com";
        test_user = "test";
        test_uri = "http://" + test_domain + "/users/" + test_user;
        test_account = "acct:" + test_user + "@" + test_domain;
    }
    
    http::request<http::string_body> create_webfinger_request(const std::string& resource) {
        http::request<http::string_body> req{http::verb::get, "/.well-known/webfinger?resource=" + resource, 11};
        req.set(http::field::host, test_domain);
        req.set(http::field::user_agent, "test");
        return req;
    }
    
    std::shared_ptr<MockResourceStore> public_store_;
    std::shared_ptr<MockResourceStore> private_store_;
    std::unique_ptr<WebFingerHandler> handler_;
    std::string test_domain;
    std::string test_user;
    std::string test_uri;
    std::string test_account;
};

#endif // WEBFINGER_HANDLER_TEST_HPP