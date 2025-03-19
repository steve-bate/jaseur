#include "resource_handler.hpp"
#include "logging.hpp"
#include "config.hpp"
#include <nlohmann/json.hpp>
#include <string>

namespace jaseur {

http::response<http::string_body> ResourceHandler::handle_request_impl(
    const http::request<http::string_body>& req) {
    
    http::response<http::string_body> res{http::status::ok, req.version()};
    res.set(http::field::server, fmt::format("{} {}", SERVER_NAME, VERSION));
    res.set(http::field::content_type, "application/activity+json");
    
    Logger::get().debug("Received request: {} {}", req.method_string(), req.target());
    Logger::get().debug("Headers:");
    for(const auto& header : req) {
        Logger::get().debug("  {}: {}", header.name_string(), header.value());
    }
    
    std::string scheme;
    if (req.count("X-Forwarded-Proto") > 0) {
        scheme = std::string(req["X-Forwarded-Proto"]);
        Logger::get().debug("Using forwarded protocol: {}", scheme);
    } else {
        scheme = "http";
    }
    std::string uri = scheme + "://" + std::string(req[http::field::host]) + std::string(req.target());
    
    if (!storage_->exists(uri)) {
        res.result(http::status::not_found);
        res.body() = "Resource not found";
        return res;
    }
    
    try {
        auto resource = storage_->get(uri);
        res.body() = resource.dump();
    } catch (const std::exception& e) {
        res.result(http::status::internal_server_error);
        res.body() = "Error retrieving resource";
        Logger::get().error("Error retrieving resource: {}", e.what());
    }
    return res;
}

} // namespace jaseur