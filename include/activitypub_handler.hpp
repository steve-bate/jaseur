#pragma once
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include <boost/beast/http.hpp>
#include "resource_handler.hpp"
#include "request_handler.hpp"

namespace jaseur {
namespace http = boost::beast::http;

class DeliveryService;
class LlmResponderService;

class ActivityPubHandler : public RequestHandler {
public:
    // Constructors with private resource store
    ActivityPubHandler(const Config& config);
    ActivityPubHandler(std::unique_ptr<ResourceStore> storage,
                      std::unique_ptr<ResourceStore> private_storage,
                      const Config& config);
    ActivityPubHandler(std::unique_ptr<ResourceStore> storage,
                      std::unique_ptr<ResourceStore> private_storage,
                      std::shared_ptr<DeliveryService> delivery_service,
                      const Config& config);
    ActivityPubHandler(std::unique_ptr<ResourceStore> storage,
                      std::unique_ptr<ResourceStore> private_storage,
                      std::shared_ptr<DeliveryService> delivery_service,
                      std::shared_ptr<LlmResponderService> llm_responder_service,
                      const Config& config);
                      
    bool can_handle(const http::request<http::string_body>& req) const override;

    // Method to access storage for testing purposes
    ResourceStore* get_storage() const { return storage_.get(); }
    // Method to access private storage for testing purposes
    ResourceStore* get_private_storage() const { return private_storage_.get(); }

protected:
    http::response<http::string_body> handle_request_impl(
        const http::request<http::string_body>& req) override;

    // HTTP Signature validation - made protected to allow test subclasses to override
    virtual bool validate_http_signature(const http::request<http::string_body>& req);
    
    // Bearer token validation - made protected to allow test subclasses to override
    virtual bool validate_bearer_token(const http::request<http::string_body>& req, const std::string& actor_uri);

    // Protected helper methods for testing
    bool is_local_uri(const std::string& uri) const;

private:
    bool handle_follow_activity(const nlohmann::json& activity);
    bool handle_create_activity(const nlohmann::json& activity);
    bool handle_delete_activity(const nlohmann::json& activity);
    
    bool add_to_followers_collection(const std::string& object_uri, const std::string& actor_uri);
    bool add_to_inbox_collection(const std::string& actor_uri, const std::string& activity_uri);
    bool add_to_outbox_collection(const std::string& actor_uri, const std::string& activity_uri);
    
    // Authorization methods
    bool authorize_request(const http::request<http::string_body>& req, const std::string& actor_uri);
    nlohmann::json load_actor_private_data(const std::string& actor_uri);
    
    // Request routing and processing
    bool is_inbox_request(const std::string& uri) const;
    bool is_outbox_request(const std::string& uri) const;
    http::response<http::string_body> process_inbox_request(
        const http::request<http::string_body>& req, const nlohmann::json& activity);
    http::response<http::string_body> process_outbox_request(
        const http::request<http::string_body>& req, const nlohmann::json& activity);
    
    // Activity delivery
    void deliver_to_recipients(const nlohmann::json& activity, 
                             const std::vector<std::string>& recipient_uris);
    
    // Utility functions
    std::vector<unsigned char> base64_decode(const std::string& encoded);
    
    // Private member variables
    std::unique_ptr<ResourceStore> storage_;
    std::unique_ptr<ResourceStore> private_storage_;  // Private resource store
    std::shared_ptr<DeliveryService> delivery_service_;
    std::shared_ptr<LlmResponderService> llm_responder_service_;
};
} // namespace jaseur