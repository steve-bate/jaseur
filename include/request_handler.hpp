#pragma once
#include <boost/beast/http.hpp>
#include <memory>
#include <string>
#include <unordered_set>
#include "config.hpp"

namespace jaseur {
namespace http = boost::beast::http;

class RequestHandler {
public:
    virtual ~RequestHandler() = default;

    // Initialize instance prefixes from config
    explicit RequestHandler(const Config& config);

    // Set the next handler in the chain
    void set_successor(std::shared_ptr<RequestHandler> successor) {
        successor_ = successor;
    }

    // Handle the request by checking if this handler can process it,
    // and if not, pass it to the next handler
    http::response<http::string_body> handle_request(
        const http::request<http::string_body>& req) {
        if (!this->can_handle(req)) {
            if (successor_) {
                return successor_->handle_request(req);
            }
            http::response<http::string_body> res{http::status::method_not_allowed, req.version()};
            res.set(http::field::server, "ActivityPub Server");
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::allow, ""); // Empty allow header since no methods are allowed
            res.body() = "Method not allowed";
            return res;
        }
        return handle_request_impl(req);
    }

    // Check if this handler can process the request
    virtual bool can_handle(const http::request<http::string_body>& req) const = 0;

protected:
    // Check if a URI belongs to this instance
    bool is_local_uri(const std::string& uri) const;

    // The actual request handling implementation
    virtual http::response<http::string_body> handle_request_impl(
        const http::request<http::string_body>& req) = 0;

    // The next handler in the chain
    std::shared_ptr<RequestHandler> successor_;

private:
    // Set of instance prefix URLs
    std::unordered_set<std::string> instance_prefixes_;
};

} // namespace jaseur