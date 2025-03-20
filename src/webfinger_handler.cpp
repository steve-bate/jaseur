#include "webfinger_handler.hpp"
#include "logging.hpp"
#include "config.hpp"
#include <regex>
#include <nlohmann/json.hpp>
#include <spdlog/fmt/fmt.h>

namespace jaseur {

WebFingerHandler::WebFingerHandler(const Config& config)
    : RequestHandler(config), 
      storage_(std::make_unique<FileResourceStore>("data.public")) {}

WebFingerHandler::WebFingerHandler(std::unique_ptr<ResourceStore> storage, const Config& config)
    : RequestHandler(config),
      storage_(std::move(storage)) {}

void WebFingerHandler::set_storage_dir(const string& dir) {
    auto file_store = dynamic_cast<FileResourceStore*>(storage_.get());
    if (file_store) {
        file_store->set_storage_dir(dir);
    }
}

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

optional<string> WebFingerHandler::find_resource_id(const string& resource_uri) {
    try {
        Logger::get().debug("Looking up resource ID for URI: {}", resource_uri);
        
        // Direct match with URI as id - use get() directly instead of a query
        if (storage_->exists(resource_uri)) {
            nlohmann::json actor_data = storage_->get(resource_uri);
            if (actor_data.contains("inbox")) {
                Logger::get().debug("Found direct match for resource: {}", resource_uri);
                return resource_uri;
            }
        }
        
        // If the direct ID match failed, search for resources with this URI in alsoKnownAs
        Query aka_query;
        aka_query["alsoKnownAs"] = resource_uri;
        auto aka_matches = storage_->query(aka_query);
        
        // We expect at most one match. More than one is a server error
        if (aka_matches.size() > 1) {
            Logger::get().error("Server error: Multiple resources with alsoKnownAs = {}", resource_uri);
            return std::nullopt;
        }
        
        // Check if we found one match
        if (aka_matches.size() == 1 && aka_matches[0].contains("inbox")) {
            Logger::get().debug("Found resource with alsoKnownAs = {}", resource_uri);
            return aka_matches[0]["id"].get<string>();
        }
        
        // The query above only works if alsoKnownAs is a string, not an array
        // We need to check for arrays manually
        Query has_aka_query;
        // Don't limit by type - search all resources
        auto potential_resources = storage_->query(has_aka_query);
        
        nlohmann::json matching_resource;
        int match_count = 0;
        
        for (const auto& resource : potential_resources) {
            if (!resource.contains("inbox") || !resource.contains("alsoKnownAs")) {
                continue;
            }
            
            const auto& aka = resource["alsoKnownAs"];
            
            // Skip if we already checked this case (string value)
            if (aka.is_string()) {
                continue;
            }
            
            // Check array of strings
            if (aka.is_array()) {
                for (const auto& alias : aka) {
                    if (alias.is_string() && alias.get<string>() == resource_uri) {
                        matching_resource = resource;
                        match_count++;
                        break;
                    }
                }
            }
        }
        
        // We expect at most one match. More than one is a server error
        if (match_count > 1) {
            Logger::get().error("Server error: Multiple resources with alsoKnownAs array containing {}", resource_uri);
            return std::nullopt;
        }
        
        if (match_count == 1) {
            Logger::get().debug("Found resource {} in alsoKnownAs array of resource {}", 
                resource_uri, matching_resource["id"].get<string>());
            return matching_resource["id"].get<string>();
        }
        
        Logger::get().debug("No matching resource found for URI: {}", resource_uri);
        return std::nullopt;
    } catch (const std::exception& e) {
        Logger::get().error("Error looking up resource ID: {}", e.what());
        return std::nullopt;
    } catch (...) {
        Logger::get().error("Unknown error looking up resource ID");
        return std::nullopt;
    }
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
    const http::request<http::string_body, http::basic_fields<std::allocator<char>>>& req) {
    
    Logger::get().info("Handling WebFinger request: {}", string(req.target()));
    
    http::response<http::string_body> res{http::status::ok, 11};
    res.set(http::field::server, fmt::format("{} {}", SERVER_NAME, VERSION));
    res.set(http::field::content_type, "application/jrd+json");
    try {
        // Only handle GET requests to /.well-known/webfinger
        string target = string(req.target());
        if (req.method() != http::verb::get || target.find("/.well-known/webfinger") != 0) {
            Logger::get().warn("Invalid request method or path: {} {}", std::string(req.method_string()), target);
            res.result(http::status::not_found);
            res.body() = "{\"error\": \"Not found\"}";
            return res;
        }
        // Parse query string to get resource parameter
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
            res.body() = "{\"error\": \"Missing resource parameter\"}";
            return res;
        }
        if (!is_valid_uri(*resource)) {
            Logger::get().warn("Invalid resource URI format: {}", *resource);
            res.result(http::status::bad_request);
            res.body() = "{\"error\": \"Invalid resource URI\"}";
            return res;
        }
        
        res.body() = create_webfinger_response(*resource);
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