#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "llm_responder_service.hpp"
#include "delivery_service.hpp"
#include "http_client.hpp"
#include "resource_store.hpp"
#include "logging.hpp"
#include <memory>
#include <nlohmann/json.hpp>

using namespace jaseur;
using json = nlohmann::json;
using ::testing::_;
using ::testing::Return;
using ::testing::NiceMock;

// Mock HTTP client for testing
class MockHttpClient : public HttpClient {
public:
    MOCK_METHOD2(get, HttpClient::Response(const std::string&, const std::map<std::string, std::string>&));
    MOCK_METHOD3(post, HttpClient::Response(const std::string&, const std::string&, const std::map<std::string, std::string>&));
};

// Mock resource store
class LlmMockResourceStore : public ResourceStore {
public:
    std::map<std::string, json> resources;

    bool put(const json& resource) override {
        if (!resource.contains("id")) return false;
        resources[resource["id"].get<std::string>()] = resource;
        return true;
    }

    json get(const std::string& uri) override {
        auto it = resources.find(uri);
        if (it != resources.end()) return it->second;
        return json();
    }

    bool exists(const std::string& uri) override {
        return resources.find(uri) != resources.end();
    }

    bool remove(const std::string& uri) override {
        return resources.erase(uri) > 0;
    }

    std::vector<json> query(const Query& query) override {
        std::vector<json> results;
        for (const auto& [uri, resource] : resources) {
            bool matches = true;
            for (const auto& [key, value] : query) {
                if (!resource.contains(key) || resource[key] != value) {
                    matches = false;
                    break;
                }
            }
            if (matches) results.push_back(resource);
        }
        return results;
    }

    std::unique_ptr<ResourceStore> share() override {
        auto store = std::make_unique<LlmMockResourceStore>();
        store->resources = this->resources;
        return store;
    }
};

// Create a test subclass to override the protected methods for testing
class TestLlmResponderService : public LlmResponderService {
public:
    // Use the parent constructor
    using LlmResponderService::LlmResponderService;
    
    // Override protected methods to simplify testing
    bool is_llm_responder_enabled(const std::string&) override {
        return actor_enabled;
    }
    
    // Test control variables
    bool actor_enabled = true;
};

class LlmResponderServiceTest : public ::testing::Test {
protected:
    std::shared_ptr<LlmMockResourceStore> public_store;
    std::shared_ptr<LlmMockResourceStore> private_store;
    std::shared_ptr<MockHttpClient> mock_http;
    std::shared_ptr<DeliveryService> delivery_service;
    std::unique_ptr<TestLlmResponderService> responder;
    std::string llm_endpoint;
    std::string llm_model;

    void SetUp() override {
        Logger::init("debug");
        public_store = std::make_shared<LlmMockResourceStore>();
        private_store = std::make_shared<LlmMockResourceStore>();
        mock_http = std::make_shared<NiceMock<MockHttpClient>>();
        delivery_service = std::make_shared<DeliveryService>(public_store, private_store, mock_http, true);
        
        // Define string variables before passing them to the constructor
        llm_endpoint = "http://localhost:11434/api/generate";
        llm_model = "mistral";
        
        // Set up the LLM responder with our test subclass
        responder = std::make_unique<TestLlmResponderService>(
            public_store,
            private_store,
            delivery_service,
            mock_http,
            llm_endpoint,
            llm_model,
            true
        );
    }
};

TEST_F(LlmResponderServiceTest, ProcessMessageSuccess) {
    const std::string recipient = "https://example.org/users/bob";
    const std::string llm_response = "Hello! This is a test response.";
    
    std::map<std::string, std::string> headers = {{"Content-Type", "application/json"}};
    EXPECT_CALL(*mock_http, post("http://localhost:11434/api/generate", _, _))
        .WillOnce(Return(HttpClient::Response{200, headers, json{{"response", llm_response}}.dump()}));

    json activity = {
        {"type", "Create"},
        {"actor", "https://example.com/users/alice"},
        {"to", recipient},
        {"object", {
            {"type", "Note"},
            {"content", "Hello bot!"},
            {"id", "https://example.com/notes/123"}
        }}
    };

    auto result = responder->process_incoming_message(activity);

    ASSERT_FALSE(result.empty());
    EXPECT_EQ(result["type"], "Create");
    EXPECT_EQ(result["actor"], recipient);
    EXPECT_EQ(result["to"], "https://example.com/users/alice");
    ASSERT_TRUE(result["object"].is_object());
    EXPECT_EQ(result["object"]["type"], "Note");
    EXPECT_EQ(result["object"]["content"], llm_response);
    EXPECT_EQ(result["object"]["inReplyTo"], "https://example.com/notes/123");
    EXPECT_EQ(result["object"]["attributedTo"], recipient);
}


TEST_F(LlmResponderServiceTest, ProcessMessageOllamaError) {
    const std::string recipient = "https://example.org/users/bob";
    
    // Setup actor info
    json actor_info = {
        {"id", recipient},
        {"llmResponder", true}
    };
    
    std::map<std::string, std::string> headers = {{"Content-Type", "application/json"}};
    EXPECT_CALL(*mock_http, post("http://localhost:11434/api/generate", _, _))
        .WillOnce(Return(HttpClient::Response{500, headers, "Internal Server Error"}));

    json activity = {
        {"type", "Create"},
        {"actor", "https://example.com/users/alice"},
        {"to", recipient},
        {"object", {
            {"type", "Note"},
            {"content", "Hello bot!"},
            {"id", "https://example.com/notes/123"}
        }}
    };

    auto result = responder->process_incoming_message(activity);
    EXPECT_TRUE(result.empty());
}

TEST_F(LlmResponderServiceTest, ProcessInvalidActivities) {
    // Non-Create activity
    json like_activity = {
        {"type", "Like"},
        {"actor", "https://example.com/users/alice"},
        {"to", "https://example.org/users/bob"},
        {"object", "https://example.org/notes/123"}
    };
    EXPECT_TRUE(responder->process_incoming_message(like_activity).empty());

    // Missing object
    json missing_object = {
        {"type", "Create"},
        {"actor", "https://example.com/users/alice"},
        {"to", "https://example.org/users/bob"}
    };
    EXPECT_TRUE(responder->process_incoming_message(missing_object).empty());

    // Non-Note object
    json non_note = {
        {"type", "Create"},
        {"actor", "https://example.com/users/alice"},
        {"to", "https://example.org/users/bob"},
        {"object", {
            {"type", "Image"},
            {"url", "https://example.com/image.jpg"}
        }}
    };
    EXPECT_TRUE(responder->process_incoming_message(non_note).empty());

    // Missing content
    json missing_content = {
        {"type", "Create"},
        {"actor", "https://example.com/users/alice"},
        {"to", "https://example.org/users/bob"},
        {"object", {
            {"type", "Note"},
            {"id", "https://example.com/notes/123"}
        }}
    };
    EXPECT_TRUE(responder->process_incoming_message(missing_content).empty());
}

TEST_F(LlmResponderServiceTest, ProcessMessageMalformedResponse) {
    const std::string recipient = "https://example.org/users/bob";
    
    // Setup actor info
    json actor_info = {
        {"id", recipient},
        {"llmResponder", true}
    };
    
    std::map<std::string, std::string> headers = {{"Content-Type", "application/json"}};
    
    // Malformed LLM response (missing 'response' field)
    json malformed_response = {
        {"model", "mistral"}
    };
    
    EXPECT_CALL(*mock_http, post("http://localhost:11434/api/generate", _, _))
        .WillOnce(Return(HttpClient::Response{200, headers, malformed_response.dump()}));

    json activity = {
        {"type", "Create"},
        {"actor", "https://example.com/users/alice"},
        {"to", recipient},
        {"object", {
            {"type", "Note"},
            {"content", "Hello bot!"},
            {"id", "https://example.com/notes/123"}
        }}
    };

    auto result = responder->process_incoming_message(activity);
    EXPECT_TRUE(result.empty());
}