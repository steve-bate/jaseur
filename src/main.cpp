#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include <CLI/CLI.hpp>
#include "config.hpp"
#include "commands.hpp"

namespace fs = std::filesystem;

// Try to find and load configuration file
void find_and_load_config(jaseur::Config& config) {
    // First check environment variable
    const char* env_config_path = std::getenv("JASEUR_CONFIG");
    if (env_config_path && fs::exists(env_config_path)) {
        config.load_from_toml(env_config_path);
        return;
    }

    // Search for jaseur.toml in current and parent directories
    fs::path current_path = fs::current_path();
    fs::path config_file = "jaseur.toml";
    
    while (true) {
        fs::path full_path = current_path / config_file;
        if (fs::exists(full_path)) {
            config.load_from_toml(full_path.string());
            return;
        }
        
        // Stop if we reached the root directory
        if (current_path == current_path.parent_path()) {
            break;
        }
        
        // Move up to parent directory
        current_path = current_path.parent_path();
    }
}

int main(int argc, char* argv[]) {
    // Create config and load settings from different sources
    jaseur::Config config;
    
    // Load from config file first (lowest priority)
    find_and_load_config(config);
    
    // Load environment variables (middle priority)
    config.load_from_env();
    
    // Main command group
    CLI::App app{"ActivityPub Resource Management Tool"};
    app.require_subcommand(1);

    // resource subcommand group
    auto resource = app.add_subcommand("resource", "Resource management commands");
    
    // resource put subcommand
    auto resource_put = resource->add_subcommand("put", "Store a JSON file in the resource store");
    std::string resource_put_json_file;
    resource_put->add_option("json_file", resource_put_json_file, "JSON file to store")->required();

    // resource get subcommand
    auto resource_get = resource->add_subcommand("get", "Show JSON content for a URI");
    std::string resource_get_uri;
    resource_get->add_option("uri", resource_get_uri, "Resource URI")->required();

    // resource list subcommand
    auto resource_list = resource->add_subcommand("list", "List all resources and their details");

    // resource post subcommand (replaces send-note)
    auto resource_post = resource->add_subcommand("post", "Post a note or other content to an actor's outbox");
    std::string resource_post_token;
    resource_post->add_option("--token", resource_post_token, "Authorization Bearer token");

    // resource path subcommand
    auto resource_path = resource->add_subcommand("path", "Show the file path for a resource");
    std::string resource_path_uri;
    resource_path->add_option("uri", resource_path_uri, "Resource URI")->required();
    
    // Add serve subcommand
    auto serve = app.add_subcommand("serve", "Start the ActivityPub server");
    std::string config_file = "jaseur.toml";
    std::string bind_address, data_dir, private_dir, allowed_ips, blocked_ips, ollama_endpoint, ollama_model;
    int port = 0;
    bool debug_mode = false;
    bool enable_llm = false;
    
    serve->add_option("--config", config_file, "Configuration file (default: jaseur.toml)");
    serve->add_flag("--debug", debug_mode, "Enable debug logging");
    serve->add_flag("--enable-llm", enable_llm, "Enable LLM responder service");
    serve->add_option("--bind-address", bind_address, "Address to bind to (default: 0.0.0.0)");
    serve->add_option("--port", port, "Port to listen on (default: 8000)");
    serve->add_option("--data.public", data_dir, "AP data directory (default: data)");
    serve->add_option("--data.private", private_dir, "Private key directory (default: data/private)");
    serve->add_option("--network.allow", allowed_ips, "Semicolon-separated list of allowed IP addresses, subnets (CIDR), or domains");
    serve->add_option("--network.block", blocked_ips, "Semicolon-separated list of blocked IP addresses, subnets (CIDR), or domains");
    serve->add_option("--ollama-endpoint", ollama_endpoint, "Ollama API endpoint");
    serve->add_option("--ollama-model", ollama_model, "Ollama model to use");

    // actor subcommand group
    auto actor = app.add_subcommand("actor", "Actor management commands");

    // actor create subcommand
    auto create_actor = actor->add_subcommand("create", "Create a new actor and its collections");
    std::string create_actor_uri;
    std::string create_actor_userid;
    std::string create_actor_name;
    create_actor->add_option("uri", create_actor_uri, "Actor URI")->required();
    create_actor->add_option("--userid", create_actor_userid, "User ID (defaults to last path segment of URI)");
    create_actor->add_option("--name", create_actor_name, "Display name");

    // actor purge subcommand
    auto actor_purge = actor->add_subcommand("purge", "Remove an actor and all attributed resources");
    std::string actor_purge_uri;
    actor_purge->add_option("uri", actor_purge_uri, "Actor URI")->required();

    // actor list subcommand
    auto actor_list = actor->add_subcommand("list", "List all actors and their file hashes");

    // inbox subcommand group
    auto inbox = app.add_subcommand("inbox", "Inbox management commands");

    // inbox list subcommand
    auto inbox_list = inbox->add_subcommand("list", "List contents of an actor's inbox");
    std::string inbox_list_uri;
    inbox_list->add_option("uri", inbox_list_uri, "Actor URI")->required();

    // inbox purge subcommand
    auto inbox_purge = inbox->add_subcommand("purge", "Remove all items from an actor's inbox");
    std::string inbox_purge_uri;
    inbox_purge->add_option("uri", inbox_purge_uri, "Actor URI")->required();

    // outbox subcommand group
    auto outbox = app.add_subcommand("outbox", "Outbox management commands");

    // outbox list subcommand
    auto outbox_list = outbox->add_subcommand("list", "List contents of an actor's outbox");
    std::string outbox_list_uri;
    outbox_list->add_option("uri", outbox_list_uri, "Actor URI")->required();

    // outbox purge subcommand
    auto outbox_purge = outbox->add_subcommand("purge", "Remove all items from an actor's outbox");
    std::string outbox_purge_uri;
    outbox_purge->add_option("uri", outbox_purge_uri, "Actor URI")->required();

    try {
        app.parse(argc, argv);
        
        // Load command line arguments not handled by CLI11 (highest priority)
        config.load_from_args(argc, argv);
        
        // For the serve command, try to load config from the specified file
        if (*serve) {
            // Load from the specified config file if not the default
            if (config_file != "jaseur.toml") {
                config.load_from_toml(config_file);
            }
            
            // Update config with CLI options
            if (debug_mode) config.set("debug", debug_mode);
            if (enable_llm) config.set("enable-llm", enable_llm);
            if (!bind_address.empty()) config.set("bind-address", bind_address);
            if (port > 0) config.set("port", port);
            if (!data_dir.empty()) config.set("data.public", data_dir);
            if (!private_dir.empty()) config.set("data.private", private_dir);
            if (!allowed_ips.empty()) config.set("network.allow", allowed_ips);
            if (!blocked_ips.empty()) config.set("network.block", blocked_ips);
            if (!ollama_endpoint.empty()) config.set("ollama.endpoint", ollama_endpoint);
            if (!ollama_model.empty()) config.set("ollama.model", ollama_model);
        }

        // Handle subcommands
        if (*resource_put) {
            return jaseur::resource_put_command(resource_put_json_file, config) ? 0 : 1;
        }
        else if (*resource_get) {
            return jaseur::resource_get_command(resource_get_uri, config) ? 0 : 1;
        }
        else if (*resource_list) {
            return jaseur::resource_list_command(config) ? 0 : 1;
        }
        else if (*resource_post) {
            return jaseur::resource_post_command(resource_post_token) ? 0 : 1;
        }
        else if (*resource_path) {
            return jaseur::resource_path_command(resource_path_uri, config) ? 0 : 1;
        }
        else if (*serve) {
            return jaseur::serve_command(config) ? 0 : 1;
        }
        else if (*actor_purge) {
            return jaseur::actor_purge_command(actor_purge_uri, config) ? 0 : 1;
        }
        else if (*actor_list) {
            return jaseur::actor_list_command(config) ? 0 : 1;
        }
        else if (*create_actor) {
            return jaseur::actor_create_command(create_actor_uri, create_actor_userid.empty() ?
                jaseur::extract_last_path_segment(create_actor_uri) : create_actor_userid,
                config, create_actor_name) ? 0 : 1;
        }
        else if (*inbox_list) {
            return jaseur::inbox_list_command(inbox_list_uri, config) ? 0 : 1;
        }
        else if (*inbox_purge) {
            return jaseur::inbox_purge_command(inbox_purge_uri, config) ? 0 : 1;
        }
        else if (*outbox_list) {
            return jaseur::outbox_list_command(outbox_list_uri, config) ? 0 : 1;
        }
        else if (*outbox_purge) {
            return jaseur::outbox_purge_command(outbox_purge_uri, config) ? 0 : 1;
        }

    } catch (const CLI::ParseError &e) {
        return app.exit(e);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}