#include "request_handler.hpp"
#include "logging.hpp"
#include <regex>

namespace jaseur {

RequestHandler::RequestHandler(const Config& config)
    : config_(config) {
    // Get instances table from config
    auto instances = config.get_table("instances");
    for (const auto& [name, instance] : instances) {
        auto prefix_it = instance.find("prefix_url");
        if (prefix_it != instance.end()) {
            instance_prefixes_.insert(prefix_it->second);
        }
    }
}

bool RequestHandler::is_local_uri(const std::string& uri) const {
    // Extract scheme and authority from URI using regex
    std::regex uri_regex(R"(^(https?://[^/]+))");
    std::smatch matches;
    if (!std::regex_search(uri, matches, uri_regex)) {
        Logger::get().warn("Invalid URI format in is_local_uri: {}", uri);
        return false;
    }

    std::string prefix = matches[1].str();
    Logger::get().debug("Checking if {} is a local URI (prefix: {})", uri, prefix);

    // Check if the URI prefix is in our set of instance prefixes
    return instance_prefixes_.find(prefix) != instance_prefixes_.end();
}

} // namespace jaseur