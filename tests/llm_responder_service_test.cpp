# include <gtest/gtest.h>
# include <gmock/gmock.h>
# include "llm_responder_service.hpp"
# include "delivery_service.hpp"
# include "http_client.hpp"
# include "resource_store.hpp"
# include <memory>
# include <nlohmann/json.hpp>

using namespace jaseur;
using json = nlohmann::json;
using ::testing::_;
using ::testing::Return;
using ::testing::NiceMock;

// Mock HTTP client for testing Ollama API calls
class MockHttpClient : public HttpClient {
public:
    MockHttpClient() {}
    MOCK_METHOD2(get, Response(const std::string&, const std::map<std::string, std::string>&));
    MOCK_METHOD3(post, Response(const std::string&, const std::string&, const std::map<std::string, std::string>&));
};

// Mock resource store for testing
class MockResourceStore : public ResourceStore {
public:
    // Mock methods
    MOCK_METHOD1(get, nlohmann::json(const std::string&));
    MOCK_METHOD1(put, bool(const nlohmann::json&));
    MOCK_METHOD1(exists, bool(const std::string&));
    MOCK_METHOD1(remove, bool(const std::string&));
    MOCK_METHOD1(query, std::vector<nlohmann::json>(const Query&));
    MOCK_METHOD1(query_ids, std::vector<std::string>(const Query&));
    
    std::unique_ptr<ResourceStore> share() override {
        auto mock = std::make_unique<NiceMock<MockResourceStore>>();
        return mock;
    }
};

// Test fixture for LlmResponderService tests
class LlmResponderServiceTest : public ::testing::Test {
protected:
    std::shared_ptr<MockResourceStore> mock_store;
    std::shared_ptr<DeliveryService> mock_delivery;
    std::shared_ptr<MockHttpClient> mock_http;
    std::unique_ptr<LlmResponderService> responder;
    
    void SetUp() override {
        mock_store = std::make_shared<MockResourceStore>();
        mock_delivery = std::make_shared<DeliveryService>(mock_store, nullptr, "", true);
        mock_http = std::make_shared<MockHttpClient>();
        responder = std::make_unique<LlmResponderService>(
            mock_store,
            mock_delivery,
            mock_http,
            "data/private",
            "http://localhost:11434/api/generate",
            "mistral",
            true
        );
    }
};

// Test checking if llmResponder is enabled
TEST_F(LlmResponderServiceTest, IsLlmResponderEnabled) {
    class TestLlmResponderService : public LlmResponderService {
    public:
        using LlmResponderService::LlmResponderService;
        using LlmResponderService::is_llm_responder_enabled;  // Make protected method accessible
        
        nlohmann::json load_actor_private_data(const std::string& actor_id) override {
            if (actor_id == "https://example.org/users/bot") {
                return {{"llmResponder", true}};
            } else if (actor_id == "https://example.org/users/user") {
                return {{"llmResponder", false}};
            } else if (actor_id == "https://example.org/users/noflag") {
                return {{"some-other-flag", true}};
            } else {
                return nlohmann::json{};
            }
        }
    };
    
    auto test_store = std::make_shared<MockResourceStore>();
    auto test_delivery = std::make_shared<DeliveryService>(test_store, nullptr, "", true);
    auto test_http = std::make_shared<MockHttpClient>();
    TestLlmResponderService test_responder(
        test_store, 
        test_delivery,
        test_http,
        "data/private",
        "http://localhost:11434/api/generate",
        "mistral",
        true
    );
    
    // Test cases
    EXPECT_TRUE(test_responder.is_llm_responder_enabled("https://example.org/users/bot"));
    EXPECT_FALSE(test_responder.is_llm_responder_enabled("https://example.org/users/user"));
    EXPECT_FALSE(test_responder.is_llm_responder_enabled("https://example.org/users/noflag"));
    EXPECT_FALSE(test_responder.is_llm_responder_enabled("https://example.org/users/nonexistent"));
}

// Test processing an incoming message from a non-responder actor
TEST_F(LlmResponderServiceTest, ProcessMessageNonResponder) {
    class TestLlmResponderService : public LlmResponderService {
    public:
        using LlmResponderService::LlmResponderService;
        
        bool is_llm_responder_enabled(const std::string&) override {
            return false;
        }

        std::string generate_llm_response(const std::string&) override {
            return "";  // Not called when responder is disabled
        }

        nlohmann::json process_incoming_message(const nlohmann::json& activity) override {
            return LlmResponderService::process_incoming_message(activity);
        }
    };
    
    auto test_store = std::make_shared<MockResourceStore>();
    auto test_delivery = std::make_shared<DeliveryService>(test_store, nullptr, "", true);
    auto test_http = std::make_shared<MockHttpClient>();
    TestLlmResponderService test_responder(
        test_store, 
        test_delivery,
        test_http,
        "data/private",
        "http://localhost:11434/api/generate",
        "mistral",
        true
    );
    
    // Create a test activity
    json activity = {
        {"type", "Create"},
        {"actor", "https://example.com/users/alice"},
        {"to", "https://example.org/users/bob"},
        {"object", {
            {"type", "Note"},
            {"content", "Hello, bot!"},
            {"id", "https://example.com/notes/123"}
        }}
    };
    
    auto result = test_responder.process_incoming_message(activity);
    EXPECT_TRUE(result.empty());
}

// Test processing an incoming message and generating a response
TEST_F(LlmResponderServiceTest, ProcessMessageSuccess) {
    class TestLlmResponderService : public LlmResponderService {
    public:
        using LlmResponderService::LlmResponderService;
        
        bool is_llm_responder_enabled(const std::string& actor_id) override {
            return actor_id == "https://example.org/users/bob"; 
        }
        
        std::string generate_llm_response(const std::string& prompt) override {
            return "This is an automated response to: " + prompt;
        }

        nlohmann::json process_incoming_message(const nlohmann::json& activity) override {
            return LlmResponderService::process_incoming_message(activity);
        }
    };
    
    auto test_store = std::make_shared<MockResourceStore>();
    auto test_delivery = std::make_shared<DeliveryService>(test_store, nullptr, "", true);
    auto test_http = std::make_shared<MockHttpClient>();
    TestLlmResponderService test_responder(
        test_store, 
        test_delivery,
        test_http,
        "data/private",
        "http://localhost:11434/api/generate",
        "mistral",
        true
    );
    
    // Create a test Create activity with a Note
    json activity = {
        {"type", "Create"},
        {"actor", "https://example.com/users/alice"},
        {"to", "https://example.org/users/bob"},
        {"object", {
            {"type", "Note"},
            {"content", "Hello, bot!"},
            {"id", "https://example.com/notes/123"}
        }}
    };
    
    json response_activity = test_responder.process_incoming_message(activity);
    EXPECT_FALSE(response_activity.empty());
    EXPECT_EQ(response_activity["type"], "Create");
    EXPECT_EQ(response_activity["actor"], "https://example.org/users/bob");
    EXPECT_EQ(response_activity["to"], "https://example.com/users/alice");
    
    const auto& note = response_activity["object"];
    EXPECT_EQ(note["type"], "Note");
    EXPECT_EQ(note["content"], "This is an automated response to: Hello, bot!");
    EXPECT_EQ(note["attributedTo"], "https://example.org/users/bob");
    EXPECT_EQ(note["to"], "https://example.com/users/alice");
    EXPECT_EQ(note["inReplyTo"], "https://example.com/notes/123");
}

// Test handling of invalid activities
TEST_F(LlmResponderServiceTest, HandleInvalidActivities) {
    class TestLlmResponderService : public LlmResponderService {
    public:
        using LlmResponderService::LlmResponderService;
        
        bool is_llm_responder_enabled(const std::string&) override {
            return true;
        }

        std::string generate_llm_response(const std::string&) override {
            return "Test response";  // Not called for invalid activities
        }

        nlohmann::json process_incoming_message(const nlohmann::json& activity) override {
            return LlmResponderService::process_incoming_message(activity);
        }
    };
    
    auto test_store = std::make_shared<MockResourceStore>();
    auto test_delivery = std::make_shared<DeliveryService>(test_store, nullptr, "", true);
    auto test_http = std::make_shared<MockHttpClient>();
    TestLlmResponderService test_responder(
        test_store, 
        test_delivery,
        test_http,
        "data/private",
        "http://localhost:11434/api/generate",
        "mistral",
        true
    );
    
    // Test with non-Create activity
    json like_activity = {
        {"type", "Like"},
        {"actor", "https://example.com/users/alice"},
        {"object", "https://example.org/notes/123"}
    };
    EXPECT_TRUE(test_responder.process_incoming_message(like_activity).empty());
    
    // Test with missing object
    json missing_object = {
        {"type", "Create"},
        {"actor", "https://example.com/users/alice"}
    };
    EXPECT_TRUE(test_responder.process_incoming_message(missing_object).empty());
    
    // Test with non-Note object
    json non_note = {
        {"type", "Create"},
        {"actor", "https://example.com/users/alice"},
        {"object", {
            {"type", "Image"},
            {"url", "https://example.com/image.jpg"}
        }}
    };
    EXPECT_TRUE(test_responder.process_incoming_message(non_note).empty());
    
    // Test with Note missing content
    json no_content = {
        {"type", "Create"},
        {"actor", "https://example.com/users/alice"},
        {"object", {
            {"type", "Note"},
            {"id", "https://example.com/notes/123"}
        }}
    };
    EXPECT_TRUE(test_responder.process_incoming_message(no_content).empty());
}