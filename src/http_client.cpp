#include "http_client.hpp"
#include "logging.hpp"
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <regex>

namespace jaseur {
namespace {
    namespace beast = boost::beast;
    namespace http = beast::http;
    namespace net = boost::asio;
    namespace ssl = boost::asio::ssl;
    using tcp = net::ip::tcp;
}

class BoostHttpClient : public HttpClient {
public:
    BoostHttpClient() 
        : ioc_()
        , ssl_context_(ssl::context::tlsv12_client) {
        // Set up SSL context with default options
        ssl_context_.set_default_verify_paths();
        ssl_context_.set_verify_mode(ssl::verify_peer);
    }

    Response get(const std::string& url,
                const std::map<std::string, std::string>& headers) override {
        return send_request(url, http::verb::get, "", headers);
    }

    Response post(const std::string& url,
                 const std::string& body,
                 const std::map<std::string, std::string>& headers) override {
        return send_request(url, http::verb::post, body, headers);
    }

private:
    net::io_context ioc_;
    ssl::context ssl_context_;

    Response send_request(const std::string& url,
                        http::verb method,
                        const std::string& body,
                        const std::map<std::string, std::string>& headers) {
        try {
            // Parse URL and strip fragment
            std::regex url_regex("(https?)://([^:/]+)(?::(\\d+))?(/[^#]*)?(?:#.*)?");
            std::smatch matches;
            if (!std::regex_match(url, matches, url_regex)) {
                throw std::runtime_error("Invalid URL");
            }

            std::string protocol = matches[1].str();
            std::string host = matches[2].str();
            std::string port = matches[3].matched ? matches[3].str() : (protocol == "https" ? "443" : "80");
            std::string target = matches[4].matched ? matches[4].str() : "/";
            bool use_ssl = (protocol == "https");

            // Set up connection
            tcp::resolver resolver(ioc_);
            auto const results = resolver.resolve(host, port);

            Response response;

            if (use_ssl) {
                // HTTPS connection
                beast::ssl_stream<beast::tcp_stream> stream(ioc_, ssl_context_);
                
                // Set SNI hostname
                if(!SSL_set_tlsext_host_name(stream.native_handle(), host.c_str())) {
                    throw beast::system_error(
                        beast::error_code(
                            static_cast<int>(::ERR_get_error()),
                            net::error::get_ssl_category()),
                        "Failed to set SNI hostname");
                }

                // Connect and perform SSL handshake
                beast::get_lowest_layer(stream).connect(results);
                stream.handshake(ssl::stream_base::client);

                // Build request
                http::request<http::string_body> req{method, target, 11};
                req.set(http::field::host, host);
                req.set(http::field::user_agent, "ActivityPub/1.0");
                
                // Add custom headers
                for (const auto& [name, value] : headers) {
                    req.set(name, value);
                }

                if (!body.empty()) {
                    req.body() = body;
                    req.prepare_payload();
                }

                // Send request
                http::write(stream, req);

                // Receive response
                beast::flat_buffer buffer;
                http::response<http::string_body> res;
                http::read(stream, buffer, res);

                // Fill response struct
                response.status_code = res.result_int();
                response.body = res.body();
                for(auto const& field : res) {
                    response.headers[std::string(field.name_string())] = std::string(field.value());
                }

                // Gracefully close the SSL stream
                beast::error_code ec;
                stream.shutdown(ec);
                if(ec && ec != net::error::eof && ec != ssl::error::stream_truncated) {
                    // Log the error but don't throw, as the HTTP transaction has already completed
                    spdlog::warn("SSL shutdown error: {}", ec.message());
                }
            } else {
                // HTTP connection
                beast::tcp_stream stream(ioc_);
                stream.connect(results);

                // Build request
                http::request<http::string_body> req{method, target, 11};
                req.set(http::field::host, host);
                req.set(http::field::user_agent, "ActivityPub/1.0");
                
                // Add custom headers
                for (const auto& [name, value] : headers) {
                    req.set(name, value);
                }

                if (!body.empty()) {
                    req.body() = body;
                    req.prepare_payload();
                }

                // Send request
                http::write(stream, req);

                // Receive response
                beast::flat_buffer buffer;
                http::response<http::string_body> res;
                http::read(stream, buffer, res);

                // Fill response struct
                response.status_code = res.result_int();
                response.body = res.body();
                for(auto const& field : res) {
                    response.headers[std::string(field.name_string())] = std::string(field.value());
                }

                // Gracefully close the socket
                beast::error_code ec;
                stream.socket().shutdown(tcp::socket::shutdown_both, ec);
            }

            return response;
        }
        catch(std::exception const& e) {
            spdlog::error("HTTP request failed: {}", e.what());
            return Response{500, {}, "Internal error: " + std::string(e.what())};
        }
    }
};

// Factory function to create HttpClient instances
std::unique_ptr<HttpClient> create_http_client() {
    return std::make_unique<BoostHttpClient>();
}

} // namespace jaseur