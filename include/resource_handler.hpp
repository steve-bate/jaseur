#ifndef RESOURCE_HANDLER_HPP
#define RESOURCE_HANDLER_HPP
#include "request_handler.hpp"
#include "resource_store.hpp"
#include <memory>
namespace jaseur {
class ResourceHandler : public RequestHandler {
public:
    explicit ResourceHandler(std::shared_ptr<ResourceStore> storage) 
        : storage_(storage) {}
        
    bool can_handle(const http::request<http::string_body>& /*req*/) const override {
        return true;  // ResourceHandler can handle any path
    }
protected:
    http::response<http::string_body> handle_request_impl(
        const http::request<http::string_body>& req) override;
private:
    std::shared_ptr<ResourceStore> storage_;
};
} // namespace jaseur
#endif // RESOURCE_HANDLER_HPP