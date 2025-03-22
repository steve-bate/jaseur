#pragma once

#include <string>
#include <filesystem>
#include <nlohmann/json.hpp>
#include "config.hpp"
#include "resource_store.hpp"

namespace jaseur {

// Actor management commands
bool actor_create_command(const std::string &uri, const std::string &userid, const Config &config, const std::string &name = "");
bool actor_purge_command(const std::string& actor_uri, const Config &config);
bool actor_list_command(const Config &config);

// Collection management commands
bool collection_list_command(const std::string& actor_uri, const Config &config, const std::string& collection_name);
bool collection_purge_command(const std::string& actor_uri, const Config &config, const std::string& collection_name);

// Inbox management commands
bool inbox_list_command(const std::string& actor_uri, const Config &config);
bool inbox_purge_command(const std::string& actor_uri, const Config &config);

// Outbox management commands
bool outbox_list_command(const std::string& actor_uri, const Config &config);
bool outbox_purge_command(const std::string& actor_uri, const Config &config);

// Resource management commands
bool resource_get_command(const std::string& uri, const Config& config);
bool resource_put_command(const std::string& json_file_path, const Config& config);
bool resource_post_command(const std::string& token);
bool resource_list_command(const Config& config);
bool resource_path_command(const std::string& uri, const Config& config);

// Server command
bool serve_command(const Config& config);

// Helper functions
std::string extract_last_path_segment(const std::string& uri);
std::vector<std::string> parse_address_list(const std::string& address_list);
nlohmann::json create_ordered_collection(const std::string& id, const std::string& actor_uri);
std::string get_base_url(const std::string& actor_uri);
std::string prompt_with_default(const std::string& prompt, const std::string& default_value);

} // namespace jaseur