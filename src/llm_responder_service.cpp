#include "llm_responder_service.hpp"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <spdlog/spdlog.h>
#include "logging.hpp"

namespace jaseur {

LlmResponderService::LlmResponderService(
    std::shared_ptr<ResourceStore> resource_store,
    std::shared_ptr<ResourceStore> private_store,
    std::shared_ptr<DeliveryService> delivery_service,
    std::shared_ptr<HttpClient> http_client,
    std::string llm_endpoint,
    std::string llm_model,
    bool no_filesystem)
    : resource_store_(std::move(resource_store))
    , private_store_(std::move(private_store))
    , delivery_service_(std::move(delivery_service))
    , http_client_(std::move(http_client))
    , llm_endpoint_(std::move(llm_endpoint))
    , llm_model_(std::move(llm_model))
    , no_filesystem_(no_filesystem) {
}

nlohmann::json LlmResponderService::process_incoming_message(const nlohmann::json& activity) {
    // Verify this is a Create activity with a Note object
    if (!activity.contains("type") || activity["type"] != "Create") {
        return nlohmann::json();
    }

    if (!activity.contains("object") || !activity["object"].is_object()) {
        return nlohmann::json();
    }

    const auto& object = activity["object"];
    if (!object.contains("type") || object["type"] != "Note") {
        return nlohmann::json();
    }

    if (!object.contains("content") || !object["content"].is_string()) {
        return nlohmann::json();
    }

    // Get recipient
    if (!activity.contains("to")) {
        return nlohmann::json();
    }
    std::string recipient;
    if (activity["to"].is_string()) {
        recipient = activity["to"].get<std::string>();
    } else if (activity["to"].is_array() && !activity["to"].empty() && activity["to"][0].is_string()) {
        recipient = activity["to"][0].get<std::string>();
    } else {
        return nlohmann::json();
    }

    // Check if recipient has LLM responder enabled
    if (!is_llm_responder_enabled(recipient)) {
        return nlohmann::json();
    }

    // Generate response using LLM
    std::string response = generate_llm_response(object["content"].get<std::string>());
    
    if (response.empty()) {
        return nlohmann::json();
    }

    // Return the response activity
    return prepare_response_activity(activity, response);
}

bool LlmResponderService::is_llm_responder_enabled(const std::string& actor_id) {
    nlohmann::json private_data = load_actor_private_data(actor_id);
    if (!private_data.contains("llmResponder")) {
        return false;
    }
    return private_data["llmResponder"].get<bool>();
}

std::string LlmResponderService::generate_llm_response(const std::string& prompt) {
    nlohmann::json request = nlohmann::json::object({
        {"model", llm_model_},
        {"prompt", prompt},
        {"stream", false}
    });

    HttpClient::Response response;
    try {
        // Set up headers
        std::map<std::string, std::string> headers = {
            {"Content-Type", "application/json"}
        };
        // Send request to LLM API
        response = http_client_->post(llm_endpoint_, request.dump(), headers);
        if (response.status_code != 200) {
            return "";
        }

        // Parse response
        auto llm_response = nlohmann::json::parse(response.body);
        if (!llm_response.contains("response")) {
            return "";
        }

        return llm_response["response"].get<std::string>();

    } catch (const std::exception& e) {
        return "";
    }
}

nlohmann::json LlmResponderService::load_actor_private_data(const std::string& actor_id) {
    if (no_filesystem_) {
        return nlohmann::json();
    }

    try {
        // Create private data ID by appending /private to actor ID
        std::string private_id = actor_id + "/private";

        // Let the private store handle any necessary hashing internally
        return private_store_->get(private_id);

    } catch (const std::exception& e) {
        Logger::get().error("Error loading private data for actor {}: {}", actor_id, e.what());
        return nlohmann::json();
    }
}

nlohmann::json LlmResponderService::prepare_response_activity(
    const nlohmann::json& original_activity,
    const std::string& response_content) {
    
    if (response_content.empty()) {
        return nlohmann::json();
    }

    try {
        // Get necessary information from original activity
        std::string response_sender;
        if (original_activity["to"].is_string()) {
            response_sender = original_activity["to"].get<std::string>();
        } else if (original_activity["to"].is_array() && !original_activity["to"].empty() && original_activity["to"][0].is_string()) {
            response_sender = original_activity["to"][0].get<std::string>();
        } else {
            return nlohmann::json();  // Invalid "to" field format
        }
        
        const std::string response_recipient = original_activity["actor"].get<std::string>();
        const std::string in_reply_to = original_activity["object"]["id"].get<std::string>();

        // Generate random ID for the response
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<unsigned long> dis;
        std::stringstream id;
        id << response_sender << "/notes/" << std::hex << dis(gen);

        // Create response Note
        nlohmann::json response_note = nlohmann::json::object({
            {"@context", "https://www.w3.org/ns/activitystreams"},
            {"type", "Note"},
            {"id", id.str()},
            {"attributedTo", response_sender},
            {"to", response_recipient},
            {"content", response_content},
            {"inReplyTo", in_reply_to}
        });

        // Create Create activity
        nlohmann::json create_activity = nlohmann::json::object({
            {"@context", "https://www.w3.org/ns/activitystreams"},
            {"type", "Create"},
            {"actor", response_sender},
            {"to", response_recipient},
            {"object", response_note}
        });

        return create_activity;

    } catch (const std::exception& e) {
        Logger::get().error("Error preparing response activity: {}", e.what());
        return nlohmann::json();
    }
}

} // namespace jaseur