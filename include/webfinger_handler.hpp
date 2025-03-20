#pragma once
#include <boost/beast/http.hpp>
#include <boost/beast/core/string.hpp>
#include <string>
#include <memory>
#include <optional>
#include "resource_store.hpp"
#include "request_handler.hpp"

namespace jaseur {
    namespace http = boost::beast::http;
    using std::string;
    using std::optional;
    
    class WebFingerHandler final : public RequestHandler {
    public:
        // Default constructor removed since we need config
        explicit WebFingerHandler(const Config& config);
        WebFingerHandler(std::unique_ptr<ResourceStore> storage, const Config& config);
        ~WebFingerHandler() override = default;
        
        bool can_handle(const http::request<http::string_body>& req) const override;
        void set_storage_dir(const string& dir);
            
    protected:
        http::response<http::string_body> handle_request_impl(
            const http::request<http::string_body>& req) override;
    private:
        optional<string> parse_resource_param(const string& query_string);
        bool is_valid_uri(const string& uri);
        optional<string> find_resource_id(const string& resource_uri);
        bool has_actor_inbox(const string& resource);
        string create_webfinger_response(const string& resource);
        std::unique_ptr<ResourceStore> storage_;
    };
} // namespace jaseur