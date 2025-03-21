#include "delivery_service.hpp"
#include "mock_http_client.hpp"
#include "mock_resource_store.hpp"
#include "logging.hpp"
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <memory>
#include <string>
#include <filesystem>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace fs = std::filesystem;

namespace jaseur {
namespace test {

class DeliveryServiceTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize logger
        Logger::init();
        
        Logger::get().info("Setting up DeliveryServiceTest");
        
        // Create a test directory for private keys
        private_keys_dir_ = "test_private_keys";
        if (fs::exists(private_keys_dir_)) {
            Logger::get().info("Removing existing test directory: {}", private_keys_dir_);
            fs::remove_all(private_keys_dir_);
        }
        Logger::get().info("Creating test directory: {}", private_keys_dir_);
        fs::create_directory(private_keys_dir_);
        
        // Create mock objects
        mock_public_store_ = std::make_shared<MockResourceStore>();
        mock_private_store_ = std::make_shared<MockResourceStore>();
        mock_client_ = std::make_shared<MockHttpClient>();
        
        // Create test service
        service_ = std::make_unique<DeliveryService>(mock_public_store_, mock_private_store_, mock_client_);
        
        Logger::get().info("Creating test keypair for actor1");
        // Create a test RSA key pair for actor1
        create_test_keypair("https://example.com/users/actor1");
        
        // Add test actors to the resource store
        nlohmann::json actor1 = {
            {"id", "https://example.com/users/actor1"},
            {"type", "Person"},
            {"inbox", "https://example.com/users/actor1/inbox"},
            {"outbox", "https://example.com/users/actor1/outbox"},
            {"publicKey", {
                {"id", "https://example.com/users/actor1#main-key"},
                {"owner", "https://example.com/users/actor1"},
                {"publicKeyPem", "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Hdj9Z8SO0Z1FHmT9AeF\nXgwAYx8znrJAWZ/K7ScwS0QiH1UtB5iEn/c8X+rK9y1iQzr+dsSMKQnmEQRxHjXn\ntIcZ8OYbBKT+F5UQFJqNS2YTaFIr0I4UIGvhP7l0dbLbEHpHzd+3aHcpUAqjLKu2\nuP4iKEYfGFihYG5r3REP5bdlcY8SHGXZPHdEgOFrTpyoUVCDkw4n3Aa8avbW0JYm\ngLUVKnKjzBTZ0NZS+yHzPLVzYCo7NTdHGCo9uK1uUJgViQdoeRlKGgxvFDb29URh\nKNWsKKoaIgLTzNpgJj4de0KgeUa9rZiy0Y+1gP26tLOgGCYGvedtuSYV+5yXCH5u\nHQIDAQAB\n-----END PUBLIC KEY-----\n"}
            }}
        };
        
        nlohmann::json actor2 = {
            {"id", "https://example.org/users/actor2"},
            {"type", "Person"},
            {"inbox", "https://example.org/users/actor2/inbox"},
            {"outbox", "https://example.org/users/actor2/outbox"}
        };
        
        mock_public_store_->add_resource(actor1["id"], actor1);
        mock_public_store_->add_resource(actor2["id"], actor2);
        
        // Configure mock HTTP client to handle remote actor requests
        mock_client_->set_get_handler([this](const std::string& url, const std::map<std::string, std::string>&) {
            if (url == "https://example.net/users/actor3") {
                nlohmann::json actor3 = {
                    {"id", "https://example.net/users/actor3"},
                    {"type", "Person"},
                    {"inbox", "https://example.net/users/actor3/inbox"},
                    {"outbox", "https://example.net/users/actor3/outbox"}
                };
                return HttpClient::Response{200, {{"Content-Type", "application/activity+json"}}, actor3.dump()};
            }
            return HttpClient::Response{404, {}, "Not Found"};
        });
        
        // Configure mock HTTP client to handle POST requests to inboxes
        mock_client_->set_post_handler([](const std::string&, const std::string&, const std::map<std::string, std::string>&) {
            return HttpClient::Response{202, {}, "Accepted"};
        });
    }
    
    void TearDown() override {
        // Clean up the test directory
        if (fs::exists(private_keys_dir_)) {
            fs::remove_all(private_keys_dir_);
        }
    }
    
    void create_test_keypair(const std::string& actor_id) {
        Logger::get().info("Creating test keypair for actor: {}", actor_id);

        // Create an RSA key pair
        EVP_PKEY* pkey = EVP_PKEY_new();
        ASSERT_NE(pkey, nullptr);
        
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        ASSERT_NE(ctx, nullptr);
        
        ASSERT_EQ(EVP_PKEY_keygen_init(ctx), 1);
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048), 1);
        ASSERT_EQ(EVP_PKEY_keygen(ctx, &pkey), 1);
        
        EVP_PKEY_CTX_free(ctx);
        
        // Create a temporary file to store the private key PEM data
        std::stringstream pem_data;
        FILE* tmp = tmpfile();
        ASSERT_NE(tmp, nullptr);
        ASSERT_EQ(PEM_write_PrivateKey(tmp, pkey, nullptr, nullptr, 0, nullptr, nullptr), 1);
        
        // Read the PEM data back
        rewind(tmp);
        char buffer[4096];
        size_t bytes;
        while ((bytes = fread(buffer, 1, sizeof(buffer), tmp)) > 0) {
            pem_data.write(buffer, bytes);
        }
        fclose(tmp);

        // Verify we got PEM data
        std::string pem_str = pem_data.str();
        ASSERT_FALSE(pem_str.empty()) << "Failed to generate PEM data";
        ASSERT_NE(pem_str.find("-----BEGIN PRIVATE KEY-----"), std::string::npos) << "Invalid PEM data";
        
        // Create the key identifier and hash it
        std::string key_id = actor_id + "/private";
        Logger::get().info("Test creating private key for ID: {}", key_id);
        
        // Create JSON data with id and privateKey
        nlohmann::json key_data;
        key_data["id"] = key_id;
        key_data["privateKey"] = pem_str;
        
        mock_private_store_->put(key_data);
        
        Logger::get().info("Successfully created test keypair");
    }
    
    std::shared_ptr<MockResourceStore> mock_public_store_;
    std::shared_ptr<MockResourceStore> mock_private_store_;
    std::shared_ptr<MockHttpClient> mock_client_;
    std::unique_ptr<DeliveryService> service_;
    std::string private_keys_dir_;
};

// Test getting the private key for an actor
TEST_F(DeliveryServiceTest, GetActorPrivateKey) {
    // Should be able to get the private key for actor1
    std::string key = service_->get_actor_private_key("https://example.com/users/actor1");
    ASSERT_FALSE(key.empty());
    
    // Should not be able to get a key for a non-existent actor
    std::string missing_key = service_->get_actor_private_key("https://example.com/users/non-existent");
    ASSERT_TRUE(missing_key.empty());
}

// Test resolving recipient inboxes
TEST_F(DeliveryServiceTest, ResolveRecipientInboxes) {
    // Test with a string "to" field
    nlohmann::json activity1 = {
        {"type", "Create"},
        {"actor", "https://example.com/users/actor1"},
        {"to", "https://example.org/users/actor2"}
    };
    
    auto inboxes1 = service_->resolve_recipient_inboxes(activity1);
    ASSERT_EQ(inboxes1.size(), 1);
    ASSERT_TRUE(inboxes1.find("https://example.org/users/actor2/inbox") != inboxes1.end());
    
    // Test with an array "to" field
    nlohmann::json activity2 = {
        {"type", "Create"},
        {"actor", "https://example.com/users/actor1"},
        {"to", {"https://example.org/users/actor2", "https://example.net/users/actor3"}}
    };
    
    auto inboxes2 = service_->resolve_recipient_inboxes(activity2);
    ASSERT_EQ(inboxes2.size(), 2);
    ASSERT_TRUE(inboxes2.find("https://example.org/users/actor2/inbox") != inboxes2.end());
    ASSERT_TRUE(inboxes2.find("https://example.net/users/actor3/inbox") != inboxes2.end());
    
    // Test with a missing "to" field
    nlohmann::json activity3 = {
        {"type", "Create"},
        {"actor", "https://example.com/users/actor1"}
    };
    
    auto inboxes3 = service_->resolve_recipient_inboxes(activity3);
    ASSERT_TRUE(inboxes3.empty());
    
    // Verify remote actor was added to the resource store
    ASSERT_TRUE(mock_public_store_->exists("https://example.net/users/actor3"));
}

// Test creating signature headers
TEST_F(DeliveryServiceTest, CreateSignatureHeaders) {
    std::string actor_id = "https://example.com/users/actor1";
    std::string target_inbox = "https://example.org/users/actor2/inbox";
    std::string body = "{\"type\":\"Create\",\"actor\":\"https://example.com/users/actor1\"}";
    
    auto headers = service_->create_signature_headers(actor_id, target_inbox, body);
    
    // Check that required headers are present
    ASSERT_TRUE(headers.find("Host") != headers.end());
    ASSERT_TRUE(headers.find("Date") != headers.end());
    ASSERT_TRUE(headers.find("Digest") != headers.end());
    ASSERT_TRUE(headers.find("Signature") != headers.end());
    ASSERT_TRUE(headers.find("Content-Type") != headers.end());
    
    // Check the Signature header format
    std::string signature = headers["Signature"];
    ASSERT_TRUE(signature.find("keyId=\"https://example.com/users/actor1#main-key\"") != std::string::npos);
    ASSERT_TRUE(signature.find("algorithm=\"rsa-sha256\"") != std::string::npos);
    ASSERT_TRUE(signature.find("headers=\"(request-target) host date digest\"") != std::string::npos);
    ASSERT_TRUE(signature.find("signature=\"") != std::string::npos);
}

// Test sending to an inbox
TEST_F(DeliveryServiceTest, SendToInbox) {
    std::string inbox_url = "https://example.org/users/actor2/inbox";
    nlohmann::json activity = {
        {"type", "Create"},
        {"actor", "https://example.com/users/actor1"},
        {"to", "https://example.org/users/actor2"}
    };
    std::map<std::string, std::string> headers = {
        {"Content-Type", "application/activity+json"}
    };
    
    // Test successful delivery
    bool success = service_->send_to_inbox(inbox_url, activity, headers);
    ASSERT_TRUE(success);
    ASSERT_EQ(mock_client_->last_post_url(), inbox_url);
    ASSERT_EQ(mock_client_->last_post_body(), activity.dump());
    
    // Verify headers were passed correctly
    ASSERT_EQ(mock_client_->last_post_headers().at("Content-Type"), "application/activity+json");
    
    // Configure mock client to return an error
    mock_client_->set_post_handler([](const std::string&, const std::string&, const std::map<std::string, std::string>&) {
        return HttpClient::Response{500, {}, "Internal Server Error"};
    });
    
    // Test failed delivery
    success = service_->send_to_inbox(inbox_url, activity, headers);
    ASSERT_FALSE(success);
}

// Test the full delivery process
TEST_F(DeliveryServiceTest, Deliver) {
    nlohmann::json activity = {
        {"type", "Create"},
        {"actor", "https://example.com/users/actor1"},
        {"to", {"https://example.org/users/actor2", "https://example.net/users/actor3"}}
    };
    
    // Configure mock client to return success
    mock_client_->set_post_handler([](const std::string&, const std::string&, const std::map<std::string, std::string>&) {
        return HttpClient::Response{202, {}, "Accepted"};
    });
    
    // Test successful delivery to all inboxes
    bool success = service_->deliver(activity, "https://example.com/users/actor1");
    ASSERT_TRUE(success);
    
    // Configure mock client to return an error for one inbox
    int call_count = 0;
    mock_client_->set_post_handler([&call_count](const std::string& url, const std::string&, const std::map<std::string, std::string>&) {
        call_count++;
        if (url == "https://example.org/users/actor2/inbox") {
            return HttpClient::Response{500, {}, "Internal Server Error"};
        }
        return HttpClient::Response{202, {}, "Accepted"};
    });
    
    // Test partial delivery failure
    success = service_->deliver(activity, "https://example.com/users/actor1");
    ASSERT_FALSE(success);
    ASSERT_EQ(call_count, 2); // Both inboxes were attempted
}

} // namespace test
} // namespace jaseur