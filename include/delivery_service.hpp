#pragma once

#include <string>
#include <vector>
#include <set>
#include <memory>
#include <nlohmann/json.hpp>
#include "resource_store.hpp"

namespace jaseur {

// Forward declarations
class HttpClient;

/**
 * DeliveryService handles the delivery of ActivityPub documents to recipient inboxes
 * following the specification in delivery.md
 */
class DeliveryService {
public:
    DeliveryService(std::shared_ptr<ResourceStore> public_store, 
                   std::shared_ptr<ResourceStore> private_store,
                   std::shared_ptr<HttpClient> http_client,
                   bool no_filesystem = false);
    
    virtual ~DeliveryService() = default;
    
    /**
     * Deliver an ActivityPub document to all recipients specified in its "to" field
     * 
     * @param activity The ActivityPub activity to deliver
     * @param actor_id Optional ID of the actor who is sending this activity. If not provided,
     *                 the actor will be extracted from the activity's "actor" field.
     * @return true if delivery was successful to all recipients, false otherwise
     */
    virtual bool deliver(const nlohmann::json& activity, const std::string& actor_id = "");
    
    /**
     * Get the private key for an actor
     * 
     * @param actor_id The ID of the actor
     * @return The private key as a string, or empty string if not found
     */
    virtual std::string get_actor_private_key(const std::string& actor_id);
    
    /**
     * Resolve the inbox URLs for all recipients in the "to" field
     * 
     * @param activity The activity containing recipients in the "to" field
     * @return A set of unique inbox URLs
     */
    virtual std::set<std::string> resolve_recipient_inboxes(const nlohmann::json& activity);
    
    /**
     * Create HTTP signature headers for a request
     * 
     * @param actor_id The ID of the actor sending the request
     * @param target_inbox The target inbox URL
     * @param body The request body
     * @return A map of header name to header value
     */
    virtual std::map<std::string, std::string> create_signature_headers(
        const std::string& actor_id, 
        const std::string& target_inbox,
        const std::string& body);
    
    /**
     * Send an HTTP POST request to a recipient inbox
     * 
     * @param inbox_url The URL of the inbox to send to
     * @param activity The activity to send
     * @param headers Additional headers to include in the request
     * @return true if delivery was successful, false otherwise
     */
    virtual bool send_to_inbox(
        const std::string& inbox_url, 
        const nlohmann::json& activity,
        const std::map<std::string, std::string>& headers);

    /**
     * Load an actor document from a remote server or local cache
     * 
     * @param actor_id The ID of the actor to load
     * @return The actor document as JSON
     */
    virtual nlohmann::json load_actor(const std::string& actor_id);

private:
    std::shared_ptr<ResourceStore> public_store_;
    std::shared_ptr<ResourceStore> private_store_;
    std::shared_ptr<HttpClient> http_client_;
    bool no_filesystem_;
};

} // namespace jaseur