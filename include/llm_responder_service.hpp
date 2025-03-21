#pragma once

#include <memory>
#include <string>
#include <random>
#include <nlohmann/json.hpp>
#include "resource_store.hpp"
#include "delivery_service.hpp"
#include "http_client.hpp"

namespace jaseur {

class LlmResponderService {
public:
    LlmResponderService(
        std::shared_ptr<ResourceStore> resource_store,
        std::shared_ptr<ResourceStore> private_store,
        std::shared_ptr<DeliveryService> delivery_service,
        std::shared_ptr<HttpClient> http_client,
        std::string llm_endpoint,
        std::string llm_model,
        bool no_filesystem = false);

    virtual ~LlmResponderService() = default;
    virtual nlohmann::json process_incoming_message(const nlohmann::json& activity);

protected:
    virtual bool is_llm_responder_enabled(const std::string& actor_id);
    virtual std::string generate_llm_response(const std::string& prompt);
    virtual nlohmann::json load_actor_private_data(const std::string& actor_id);
    nlohmann::json prepare_response_activity(const nlohmann::json& original_activity, const std::string& response_content);

private:
    std::shared_ptr<ResourceStore> resource_store_;
    std::shared_ptr<ResourceStore> private_store_;
    std::shared_ptr<DeliveryService> delivery_service_;
    std::shared_ptr<HttpClient> http_client_;
    std::string llm_endpoint_;
    std::string llm_model_;
    bool no_filesystem_;
};

} // namespace jaseur