#include "webfinger_handler.hpp"
#include "logging.hpp"
#include "config.hpp"
#include <regex>
#include <nlohmann/json.hpp>
#include <spdlog/fmt/fmt.h>

namespace jaseur {

WebFingerHandler::WebFingerHandler(std::shared_ptr<ResourceStore> public_storage,
                                    const Config& config)
    : RequestHandler(config),
      public_storage_(std::move(public_storage)) {}


bool WebFingerHandler::can_handle(const http::request<http::string_body>& req) const {
    string target = string(req.target());
    return req.method() == http::verb::get && target.find("/.well-known/webfinger") == 0;
}

optional<string> WebFingerHandler::parse_resource_param(const string& query_string) {
    // Look for resource=<value> in the query string
    std::regex resource_regex(R"((?:^|&)resource=([^&]+))");
    std::smatch matches;
    if (std::regex_search(query_string, matches, resource_regex) && matches.size() > 1) {
        Logger::get().debug("Parsed resource parameter: {}", matches[1].str());
        return matches[1].str();
    }
    Logger::get().debug("No resource parameter found in query string");
    return std::nullopt;
}

bool WebFingerHandler::is_valid_uri(const string& uri) {
    // Accept any non-empty string with a scheme followed by :
    std::regex uri_regex(R"(^[a-zA-Z][a-zA-Z0-9+.-]*:.+$)");
    bool valid = std::regex_match(uri, uri_regex);
    if (!valid) {
        Logger::get().warn("Invalid URI format: {}", uri);
    }
    return valid;
}

string WebFingerHandler::get_uri_prefix(const string& uri) {
    std::regex prefix_regex(R"((https?://[^/]+))");
    std::smatch matches;
    if (std::regex_search(uri, matches, prefix_regex) && matches.size() > 1) {
        return matches[1].str();
    }
    return "";
}

optional<string> WebFingerHandler::find_resource_id(const string& resource_uri) {
    // 1. Direct match in public store
    auto resource = public_storage_->get(resource_uri);
    if (!resource.empty()) {
        return resource["id"].get<string>();
    }

    // 2. alsoKnownAs in public store
    Query query;
    auto prefix = get_uri_prefix(resource_uri);
    query["@prefix"] = prefix;
    query["alsoKnownAs"] = resource_uri;
    resource = public_storage_->query(query);
    if (!resource.empty()) {
        return resource[0]["id"].get<string>();
    }

    return std::nullopt;
}

bool WebFingerHandler::has_actor_inbox(const string& resource) {
    try {
        auto actor_id = find_resource_id(resource);
        return actor_id.has_value();
    } catch (const std::exception& e) {
        Logger::get().error("Error checking actor inbox: {}", e.what());
        return false;
    } catch (...) {
        Logger::get().error("Unknown error checking actor inbox");
        return false;
    }
}

string WebFingerHandler::create_webfinger_response(const string& resource) {
    Logger::get().debug("Creating WebFinger response for resource: {}", resource);
    
    nlohmann::json response = {
        {"subject", resource},
        {"links", nlohmann::json::array()}
    };
    
    auto actor_id = find_resource_id(resource);
    if (actor_id) {
        Logger::get().debug("Found actor ID {} for resource {}", *actor_id, resource);
        response["links"].push_back({
            {"rel", "self"},
            {"type", "application/activity+json"},
            {"href", *actor_id}
        });
    } else {
        Logger::get().debug("No actor found for resource {}", resource);
    }
    
    return response.dump();
}

http::response<http::string_body> WebFingerHandler::handle_request_impl(
    const http::request<http::string_body>& req) {
    
    Logger::get().info("Handling WebFinger request: {}", string(req.target()));
    
    http::response<http::string_body> res{http::status::ok, 11};
    res.set(http::field::server, fmt::format("{} {}", SERVER_NAME, VERSION));
    
    // Validate Accept header - handle string_view carefully
    auto accept_it = req.find(http::field::accept);
    if (accept_it != req.end()) {
        boost::beast::string_view accept_view = accept_it->value();
        std::string accept_value{accept_view.data(), accept_view.size()};
        if (accept_value != "*/*" && accept_value.find("application/jrd+json") == std::string::npos) {
            Logger::get().warn("Invalid Accept header: {}", accept_value);
            res.result(http::status::not_acceptable);
            res.set(http::field::content_type, "application/json");
            res.body() = R"({"error": "Only application/jrd+json is supported"})";
            return res;
        }
    }

    res.set(http::field::content_type, "application/jrd+json");

    try {
        string target = string(req.target());
        if (req.method() != http::verb::get || target.find("/.well-known/webfinger") != 0) {
            Logger::get().warn("Invalid request method or path: {} {}", std::string(req.method_string()), target);
            res.result(http::status::not_found);
            res.body() = "{\"error\": \"Not found\"}";
            return res;
        }

        auto query_pos = target.find('?');
        if (query_pos == string::npos) {
            Logger::get().warn("Missing query string in request: {}", target);
            res.result(http::status::bad_request);
            res.body() = "{\"error\": \"Missing resource parameter\"}";
            return res;
        }
        
        string query = target.substr(query_pos + 1);
        auto resource = parse_resource_param(query);
        
        if (!resource || resource->empty()) {
            Logger::get().warn("Missing or empty resource parameter");
            res.result(http::status::bad_request);
            res.body() = "{\"error\": \"Missing or invalid resource parameter\"}";
            return res;
        }

        if (!is_valid_uri(*resource)) {
            Logger::get().warn("Invalid resource URI format: {}", *resource);
            res.result(http::status::bad_request);
            res.body() = "{\"error\": \"Invalid resource URI\"}";
            return res;
        }

        // Try to find the resource
        auto actor_id = find_resource_id(*resource);
        if (!actor_id) {
            Logger::get().info("Resource not found: {}", *resource);
            res.result(http::status::not_found);
            res.body() = "{\"error\": \"Resource not found\"}";
            return res;
        }

        // Create WebFinger response
        nlohmann::json response = {
            {"subject", *resource},
            {"links", nlohmann::json::array({
                {
                    {"rel", "self"},
                    {"type", "application/activity+json"},
                    {"href", *actor_id}
                }
            })}
        };

        res.body() = response.dump();
        Logger::get().info("Successfully handled WebFinger request for resource: {}", *resource);
        return res;

    } catch (const std::exception& e) {
        Logger::get().error("Error handling WebFinger request: {}", e.what());
        res.result(http::status::internal_server_error);
        res.body() = "{\"error\": \"Internal server error\"}";
        return res;
    } catch (...) {
        Logger::get().error("Unknown error handling WebFinger request");
        res.result(http::status::internal_server_error);
        res.body() = "{\"error\": \"Internal server error\"}";
        return res;
    }
}

} // namespace jaseur