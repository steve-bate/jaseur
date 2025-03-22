#include "commands.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <ctime>
#include <sstream>
#include <regex>
#include <unordered_set>
#include <set>
#include <algorithm>
#include <spdlog/spdlog.h>
#include "http_client.hpp"
#include "server.hpp"
#include "resource_handler.hpp"
#include "activitypub_handler.hpp"
#include "webfinger_handler.hpp"
#include "delivery_service.hpp"
#include "llm_responder_service.hpp"
#include "logging.hpp"

namespace fs = std::filesystem;

// Settings class declaration (could be moved to its own file later)
class Settings {
public:
    static Settings& instance() {
        static Settings settings;
        return settings;
    }

    void load() {
        std::string home = getenv("HOME");
        settings_path_ = home + "/.config/jaseur/settings.json";
        
        if (fs::exists(settings_path_)) {
            std::ifstream file(settings_path_);
            if (file.is_open()) {
                try {
                    file >> settings_;
                } catch (const std::exception& e) {
                    spdlog::warn("Failed to parse settings file: {}", e.what());
                }
            }
        }
    }

    void save() {
        fs::create_directories(fs::path(settings_path_).parent_path());
        std::ofstream file(settings_path_);
        if (file.is_open()) {
            file << settings_.dump(2);
        }
    }

    std::string get_last_actor() const {
        if (!settings_.contains("last_actor")) {
            return "";
        }
        return settings_["last_actor"].get<std::string>();
    }

    void set_last_actor(const std::string& actor) {
        settings_["last_actor"] = actor;
        save();
    }

    std::string get_last_recipient() const {
        if (!settings_.contains("last_recipient")) {
            return "";
        }
        return settings_["last_recipient"].get<std::string>();
    }

    void set_last_recipient(const std::string& recipient) {
        settings_["last_recipient"] = recipient;
        save();
    }

private:
    Settings() {
        load();
    }

    std::string settings_path_;
    nlohmann::json settings_;
};

namespace jaseur {

std::string prompt_with_default(const std::string& prompt, const std::string& default_value) {
    if (!default_value.empty()) {
        std::cout << prompt << " [" << default_value << "]: ";
    } else {
        std::cout << prompt << ": ";
    }

    std::string input;
    std::getline(std::cin, input);

    return input.empty() ? default_value : input;
}

std::string get_base_url(const std::string& actor_uri) {
    size_t pos = actor_uri.find("://");
    if (pos == std::string::npos) return "";

    pos = actor_uri.find('/', pos + 3);
    if (pos == std::string::npos) return actor_uri;

    return actor_uri.substr(0, pos);
}

std::string extract_last_path_segment(const std::string& uri) {
    std::string path = uri;
    if (!path.empty() && path.back() == '/') {
        path.pop_back();
    }
    size_t pos = path.rfind('/');
    if (pos != std::string::npos) {
        return path.substr(pos + 1);
    }
    return path;
}

nlohmann::json create_ordered_collection(const std::string& id, const std::string& actor_uri) {
    nlohmann::json collection;
    collection["@context"] = "https://www.w3.org/ns/activitystreams";
    collection["type"] = "OrderedCollection";
    collection["id"] = id;
    collection["attributedTo"] = actor_uri;
    collection["totalItems"] = 0;
    collection["orderedItems"] = nlohmann::json::array();
    return collection;
}

// Shared collection handling functions
bool collection_list_command(const std::string& actor_uri, const Config &config, const std::string& collection_name) {
    std::string storage_dir = config.get<std::string>("data.public", "data");
    FileResourceStore store(storage_dir);
    
    // Get the actor document first
    nlohmann::json actor = store.get(actor_uri);
    if (actor.empty()) {
        std::cerr << "Error: Could not find actor: " << actor_uri << std::endl;
        return false;
    }
    
    if (!actor.contains(collection_name)) {
        std::cerr << "Error: Actor document does not contain " << collection_name << " URI" << std::endl;
        return false;
    }
    std::string collection_uri = actor[collection_name];
    
    // Get the collection
    nlohmann::json collection = store.get(collection_uri);
    if (collection.empty()) {
        std::cerr << "Error: Could not find collection at URI: " << collection_uri << std::endl;
        return false;
    }
    
    // Check if it's an OrderedCollection
    if (!collection.contains("type") || collection["type"] != "OrderedCollection") {
        std::cerr << "Error: Invalid collection format - expected OrderedCollection" << std::endl;
        return false;
    }
    
    // Get the ordered items
    auto items = collection["orderedItems"];
    if (!items.is_array()) {
        std::cerr << "Error: Invalid collection format - orderedItems is not an array" << std::endl;
        return false;
    }
    
    // Print header
    std::cout << collection_name << " contents for " << actor_uri << ":" << std::endl;
    std::cout << collection_name << " URI: " << collection_uri << std::endl;
    std::cout << std::string(80, '-') << std::endl;
    std::cout << std::left << std::setw(50) << "Activity ID" 
              << std::left << std::setw(15) << "Type"
              << std::endl;
    std::cout << std::string(80, '-') << std::endl;
    
    // List all activities
    for (const auto& item : items) {
        std::string activity_uri;
        
        if (item.is_string()) {
            activity_uri = item;
        } else if (item.is_object() && item.contains("id")) {
            activity_uri = item["id"];
        } else {
            continue;
        }
        
        nlohmann::json activity = store.get(activity_uri);
        if (activity.empty()) {
            std::cerr << "Warning: Could not retrieve activity: " << activity_uri << std::endl;
            continue;
        }
        
        if (!activity.contains("type")) {
            std::cerr << "Warning: Activity missing type: " << activity_uri << std::endl;
            continue;
        }
        
        std::string id = activity_uri;
        std::string type = activity["type"];
        
        std::cout << std::left << std::setw(50) << id.substr(0, 49)
                 << std::left << std::setw(15) << type
                 << std::endl;
    }
    
    std::cout << std::string(80, '-') << std::endl;
    std::cout << "Total items: " << items.size() << std::endl;
    
    return true;
}

bool collection_purge_command(const std::string& actor_uri, const Config &config, const std::string& collection_name) {
    std::string storage_dir = config.get<std::string>("data.public", "data");
    FileResourceStore store(storage_dir);
    
    // Get the actor document first
    nlohmann::json actor = store.get(actor_uri);
    if (actor.empty()) {
        std::cerr << "Error: Could not find actor: " << actor_uri << std::endl;
        return false;
    }
    
    if (!actor.contains(collection_name)) {
        std::cerr << "Error: Actor document does not contain " << collection_name << " URI" << std::endl;
        return false;
    }
    std::string collection_uri = actor[collection_name];
    
    // Get the collection
    nlohmann::json collection = store.get(collection_uri);
    if (collection.empty()) {
        std::cerr << "Error: Could not find collection at URI: " << collection_uri << std::endl;
        return false;
    }
    
    // Check if it's an OrderedCollection
    if (!collection.contains("type") || collection["type"] != "OrderedCollection") {
        std::cerr << "Error: Invalid collection format - expected OrderedCollection" << std::endl;
        return false;
    }
    
    // Get the ordered items
    auto items = collection["orderedItems"];
    if (!items.is_array()) {
        std::cerr << "Error: Invalid collection format - orderedItems is not an array" << std::endl;
        return false;
    }
    
    std::cout << "Purging " << items.size() << " items from " << collection_name << ": " << collection_uri << std::endl;
    
    int removed_activities = 0;
    int removed_objects = 0;
    
    // Process each item in the collection
    for (const auto& item : items) {
        std::string activity_uri;
        
        if (item.is_string()) {
            activity_uri = item;
        } else if (item.is_object() && item.contains("id")) {
            activity_uri = item["id"];
        } else {
            continue;
        }
        
        // Retrieve the actual activity
        nlohmann::json activity = store.get(activity_uri);
        if (activity.empty()) {
            std::cerr << "Warning: Could not retrieve activity: " << activity_uri << std::endl;
            continue;
        }
        
        // Check if the activity has an object
        if (activity.contains("object")) {
            std::string object_uri;
            
            if (activity["object"].is_string()) {
                object_uri = activity["object"];
            } else if (activity["object"].is_object() && activity["object"].contains("id")) {
                object_uri = activity["object"]["id"];
            }
            
            // Remove the object if it's a URI
            if (!object_uri.empty()) {
                if (store.remove(object_uri)) {
                    std::cout << "Removed object: " << object_uri << std::endl;
                    removed_objects++;
                } else {
                    std::cerr << "Warning: Failed to remove object: " << object_uri << std::endl;
                }
            }
        }
        
        // Remove the activity
        if (store.remove(activity_uri)) {
            std::cout << "Removed activity: " << activity_uri << std::endl;
            removed_activities++;
        } else {
            std::cerr << "Warning: Failed to remove activity: " << activity_uri << std::endl;
        }
    }
    
    // Clear the collection
    collection["orderedItems"] = nlohmann::json::array();
    collection["totalItems"] = 0;
    
    // Save the updated collection
    if (store.put(collection)) {
        std::cout << collection_name << " purged successfully." << std::endl;
        std::cout << "Removed " << removed_activities << " activities and " << removed_objects << " objects." << std::endl;
        return true;
    } else {
        std::cerr << "Error: Failed to update the " << collection_name << " collection" << std::endl;
        return false;
    }
}

bool resource_get_command(const std::string& uri, const Config& config) {
    std::vector<std::string> storage_dirs;
    
    if (config.has("data.public")) {
        storage_dirs.push_back(config.get<std::string>("data.public", ""));
    }
    
    if (config.has("data.private")) {
        storage_dirs.push_back(config.get<std::string>("data.private", ""));
    }

    for (const auto& storage_dir : storage_dirs) {
        FileResourceStore store(storage_dir);
        nlohmann::json resource = store.get(uri);
        if (!resource.empty()) {
            std::cout << resource.dump(2) << std::endl;
            return true;
        }
    }

    std::cerr << "Error: Could not find resource: " << uri << std::endl;
    return false;
}

bool resource_put_command(const std::string& json_file_path, const Config& config) {
    // Read the JSON file
    std::ifstream file(json_file_path);
    if (!file) {
        std::cerr << "Error: Could not open file: " << json_file_path << std::endl;
        return false;
    }
    
    // Parse JSON
    nlohmann::json json_data;
    try {
        file >> json_data;
    } catch (const nlohmann::json::parse_error& e) {
        std::cerr << "Error: Invalid JSON in file: " << e.what() << std::endl;
        return false;
    }
    
    // Check for 'id' field
    if (!json_data.contains("id")) {
        std::cerr << "Error: JSON file must contain an 'id' field" << std::endl;
        return false;
    }

    // Create resource store and store the JSON
    std::string storage_dir = config.get<std::string>("data.public", "data");
    FileResourceStore store(storage_dir);
    if (!store.put(json_data)) {
        std::cerr << "Error: Failed to store the resource" << std::endl;
        return false;
    }

    return true;
}

bool actor_create_command(const std::string &uri, const std::string &userid, const Config &config, const std::string &name) {
    std::string storage_dir = config.get<std::string>("data.public", "data");
    FileResourceStore store(storage_dir);

    // Create actor document
    nlohmann::json actor;
    actor["@context"] = "https://www.w3.org/ns/activitystreams";
    actor["type"] = "Person";
    actor["id"] = uri;
    actor["name"] = name.empty() ? userid : name;
    actor["preferredUsername"] = userid;
    actor["summary"] = "ActivityPub Actor";
    actor["inbox"] = uri + "/inbox";
    actor["outbox"] = uri + "/outbox";
    actor["followers"] = uri + "/followers";
    actor["following"] = uri + "/following";
    actor["url"] = uri;
    
    // Create collections
    nlohmann::json inbox = create_ordered_collection(uri + "/inbox", uri);
    nlohmann::json outbox = create_ordered_collection(uri + "/outbox", uri);
    nlohmann::json followers = create_ordered_collection(uri + "/followers", uri);
    nlohmann::json following = create_ordered_collection(uri + "/following", uri);
    
    // Store all documents
    bool success = true;
    std::vector<std::pair<std::string, nlohmann::json>> resources = {
        {"Actor", actor},
        {"Inbox", inbox},
        {"Outbox", outbox},
        {"Followers", followers},
        {"Following", following}
    };
    
    for (const auto& [type, resource] : resources) {
        if (store.put(resource)) {
            std::string res_uri = resource["id"];
            std::cout << "Successfully stored " << type << ": " << uri << std::endl;
        } else {
            std::cerr << "Error: Failed to store " << type << std::endl;
            success = false;
        }
    }
    
    return success;
}

bool inbox_list_command(const std::string& actor_uri, const Config &config) {
    return collection_list_command(actor_uri, config, "inbox");
}

bool inbox_purge_command(const std::string& actor_uri, const Config &config) {
    return collection_purge_command(actor_uri, config, "inbox");
}

bool outbox_list_command(const std::string& actor_uri, const Config &config) {
    return collection_list_command(actor_uri, config, "outbox");
}

bool outbox_purge_command(const std::string& actor_uri, const Config &config) {
    return collection_purge_command(actor_uri, config, "outbox");
}

bool resource_post_command(const std::string& token) {
    try {
        auto& settings = Settings::instance();
        // Get the actor URI
        std::string actor_uri = prompt_with_default("Actor URI", settings.get_last_actor());
        if (actor_uri.empty()) {
            std::cerr << "Actor URI is required\n";
            return false;
        }
        settings.set_last_actor(actor_uri);

        std::string base_url = get_base_url(actor_uri);
        if (base_url.empty()) {
            std::cerr << "Could not determine base URL from actor URI\n";
            return false;
        }

        // Get the recipient
        std::string recipient = prompt_with_default("Recipient URI", settings.get_last_recipient());
        if (recipient.empty()) {
            std::cerr << "Recipient URI is required\n";
            return false;
        }
        settings.set_last_recipient(recipient);

        // Get the note content
        std::cout << "Enter note content (Ctrl+D or empty line to finish):\n";
        std::string content;
        std::string line;
        while (std::getline(std::cin, line) && !line.empty()) {
            if (!content.empty()) content += "\n";
            content += line;
        }
        if (content.empty()) {
            std::cerr << "Note content is required\n";
            return false;
        }

        // Prepare headers for authenticated requests
        std::map<std::string, std::string> headers;
        if (!token.empty()) {
            headers["Authorization"] = "Bearer " + token;
        }

        // Load the actor document to get the outbox URL
        auto client = create_http_client();
        auto actor_response = client->get(actor_uri, headers);
        if (actor_response.status_code != 200) {
            std::cerr << "Failed to load actor document: HTTP " << actor_response.status_code << "\n";
            return false;
        }

        nlohmann::json actor_doc = nlohmann::json::parse(actor_response.body);
        std::string outbox_url;

        if (actor_doc.contains("outbox")) {
            outbox_url = actor_doc["outbox"];
        } else if (actor_doc.contains("output")) {
            outbox_url = actor_doc["output"];
        } else {
            std::cerr << "Actor document does not contain outbox or output URL\n";
            return false;
        }

        // Create the Note object
        nlohmann::json note = {
            {"@context", "https://www.w3.org/ns/activitystreams"},
            {"type", "Note"},
            {"attributedTo", actor_uri},
            {"content", content},
            {"to", recipient},
            {"published", std::time(nullptr)}
        };

        // Create the Create activity
        nlohmann::json activity = {
            {"@context", "https://www.w3.org/ns/activitystreams"},
            {"type", "Create"},
            {"actor", actor_uri},
            {"object", note},
            {"to", recipient},
            {"published", std::time(nullptr)}
        };

        std::cout << "\nSending activity to " << outbox_url << ":\n";
        std::cout << activity.dump(2) << "\n\n";

        // Send the activity to the outbox with authorization header
        auto response = client->post(outbox_url, activity.dump(), headers);
        std::cout << "Response status: " << response.status_code << "\n";
        if (!response.body.empty()) {
            try {
                nlohmann::json response_json = nlohmann::json::parse(response.body);
                std::cout << "Response body:\n" << response_json.dump(2) << "\n\n";
            } catch (const std::exception& e) {
                std::cout << "Response body (raw):\n" << response.body << "\n\n";
            }
        }

        if (response.status_code < 200 || response.status_code >= 300) {
            std::cerr << "Failed to post activity to outbox: HTTP " << response.status_code << "\n";
            return false;
        }

        std::cout << "Note sent successfully!\n";
        return true;

    } catch (const std::exception& e) {
        std::cerr << "Error sending note: " << e.what() << "\n";
        return false;
    }
}

bool actor_purge_command(const std::string& actor_uri, const Config &config) {
    std::string storage_dir = config.get<std::string>("data.public", "data");
    FileResourceStore store(storage_dir);
    
    // Get the actor document first
    nlohmann::json actor = store.get(actor_uri);
    if (actor.empty()) {
        std::cerr << "Error: Could not find actor: " << actor_uri << std::endl;
        return false;
    }
    
    // First, purge inbox and outbox to clean up associated activities and objects
    if (actor.contains("inbox")) {
        inbox_purge_command(actor_uri, config);
    }
    if (actor.contains("outbox")) {
        outbox_purge_command(actor_uri, config);
    }
    
    // Get all resources from the store
    Query empty_query;
    auto all_resources = store.query(empty_query);
    
    int removed_resources = 0;
    
    // Remove all resources attributed to this actor
    for (const auto& resource : all_resources) {
        if (!resource.contains("id")) continue;
        
        bool should_remove = false;
        
        // Check if this is one of the actor's collections
        if (resource.contains("attributedTo") && 
            resource["attributedTo"] == actor_uri) {
            should_remove = true;
        }
        
        // Remove if it matches any of the actor's collection URIs
        if (actor.contains("inbox") && resource["id"] == actor["inbox"]) should_remove = true;
        if (actor.contains("outbox") && resource["id"] == actor["outbox"]) should_remove = true;
        if (actor.contains("followers") && resource["id"] == actor["followers"]) should_remove = true;
        if (actor.contains("following") && resource["id"] == actor["following"]) should_remove = true;
        
        if (should_remove) {
            std::string resource_uri = resource["id"];
            if (store.remove(resource_uri)) {
                std::cout << "Removed resource: " << resource_uri << std::endl;
                removed_resources++;
            } else {
                std::cerr << "Warning: Failed to remove resource: " << resource_uri << std::endl;
            }
        }
    }
    
    // Finally remove the actor document itself
    if (store.remove(actor_uri)) {
        std::cout << "Removed actor: " << actor_uri << std::endl;
        removed_resources++;
    } else {
        std::cerr << "Warning: Failed to remove actor document: " << actor_uri << std::endl;
    }
    
    std::cout << "Actor purged successfully." << std::endl;
    std::cout << "Total resources removed: " << removed_resources << std::endl;
    return true;
}

bool actor_list_command(const Config &config) {
    std::string storage_dir = config.get<std::string>("data.public", "data");
    FileResourceStore store(storage_dir);
    
    // Get all resources
    Query type_query;
    type_query["type"] = "Person";
    auto actors = store.query(type_query);
    
    if (actors.empty()) {
        std::cout << "No actors found in storage." << std::endl;
        return true;
    }
    
    // Print header
    std::cout << std::left << std::setw(60) << "Actor URI" << std::endl;
    std::cout << std::string(80, '-') << std::endl;
    
    // List all actors
    for (const auto& actor : actors) {
        if (!actor.contains("id")) continue;
        
        std::string uri = actor["id"];
        std::cout << std::left << std::setw(60) << uri.substr(0, 59) << std::endl;
    }
    
    std::cout << std::string(80, '-') << std::endl;
    std::cout << "Total actors: " << actors.size() << std::endl;
    
    return true;
}

bool resource_list_command(const Config& config) {
    std::string storage_dir = config.get<std::string>("data.public", "data");
    FileResourceStore store(storage_dir);
    
    // Get all resources
    Query empty_query;
    auto resources = store.query(empty_query);
    
    if (resources.empty()) {
        std::cout << "No resources found in storage." << std::endl;
        return true;
    }

    // Get instance prefixes for ownership lookup
    auto instances = config.get_table("instances");
    std::unordered_set<std::string> instance_prefixes;
    for (const auto& [name, instance] : instances) {
        auto prefix_it = instance.find("prefix_url");
        if (prefix_it != instance.end()) {
            instance_prefixes.insert(prefix_it->second);
        }
    }
    
    // Print header
    std::cout << std::left << std::setw(60) << "Resource URI" 
              << std::left << std::setw(20) << "Type"
              << std::left << std::setw(40) << "Owner"
              << std::endl;
    std::cout << std::string(120, '-') << std::endl;
    
    // List all resources
    for (const auto& resource : resources) {
        if (!resource.contains("id")) continue;
        
        std::string uri = resource["id"];
        std::string type = "-";
        if (resource.contains("type")) {
            if (resource["type"].is_string()) {
                type = resource["type"].get<std::string>();
            } else if (resource["type"].is_array() && !resource["type"].empty()) {
                type = resource["type"][0].get<std::string>();
            }
        }
        
        // Determine owner from attributedTo or actor field
        std::string owner = "-";
        if (resource.contains("attributedTo")) {
            owner = resource["attributedTo"].get<std::string>();
        } else if (resource.contains("actor")) {
            owner = resource["actor"].get<std::string>();
        } else if (type == "Create" && resource.contains("object") && 
                  resource["object"].is_object() && resource["object"].contains("attributedTo")) {
            owner = resource["object"]["attributedTo"].get<std::string>();
        }

        // For known ActivityPub actor types, try to simplify to instance prefix
        if (owner == "-" && (type == "Person" || type == "Organization" || type == "Group" || 
             type == "Service" || type == "Application")) {
            // Extract scheme and authority from owner URI
            std::regex uri_regex("^(https?://[^/]+)");
            std::smatch matches;
            if (std::regex_search(uri, matches, uri_regex)) {
                std::string prefix = matches[1].str();
                owner = prefix;
            }
        }

        std::cout << std::left << std::setw(60) << uri.substr(0, 59)
                 << std::left << std::setw(20) << type.substr(0, 19)
                 << std::left << std::setw(40) << owner.substr(0, 39)
                 << std::endl;
    }
    
    std::cout << std::string(120, '-') << std::endl;
    std::cout << "Total resources: " << resources.size() << std::endl;
    
    return true;
}

std::vector<std::string> parse_address_list(const std::string& address_list) {
    std::vector<std::string> result;
    std::stringstream ss(address_list);
    std::string addr;
    while (std::getline(ss, addr, ';')) {
        if (!addr.empty()) {
            // Trim any whitespace
            addr.erase(0, addr.find_first_not_of(" \t\r\n"));
            addr.erase(addr.find_last_not_of(" \t\r\n") + 1);
            if (!addr.empty()) {
                result.push_back(addr);
            }
        }
    }
    return result;
}

bool serve_command(const Config& config) {
    std::string address = config.get<std::string>("bind-address", "0.0.0.0");
    unsigned short port = config.get<int>("port", 8000);
    std::string data_dir = config.get<std::string>("data.public", "data");
    std::string private_data_dir = config.get<std::string>("data.private", "data/private");
    
    // For network.allow, try both string and list formats
    std::string allowed_addrs;
    auto allowed_list = config.get_list<std::string>("network.allow");
    if (!allowed_list.empty()) {
        // Join the list with semicolons
        for (const auto& addr : allowed_list) {
            if (!allowed_addrs.empty()) allowed_addrs += ";";
            allowed_addrs += addr;
        }
    } else {
        // Fall back to string format
        allowed_addrs = config.get<std::string>("network.allow", "");
    }
    
    // For network.block, try both string and list formats
    std::string blocked_addrs;
    auto blocked_list = config.get_list<std::string>("network.block");
    if (!blocked_list.empty()) {
        // Join the list with semicolons
        for (const auto& addr : blocked_list) {
            if (!blocked_addrs.empty()) blocked_addrs += ";";
            blocked_addrs += addr;
        }
    } else {
        // Fall back to string format
        blocked_addrs = config.get<std::string>("network.block", "");
    }
    
    bool debug_mode = config.get<bool>("debug", false);
    bool enable_llm = config.get<bool>("enable-llm", false);
    std::string ollama_endpoint = config.get<std::string>("ollama.endpoint", "http://localhost:11434/api/generate");
    std::string ollama_model = config.get<std::string>("ollama.model", "llama3:8B");
    
    // Parse the allowed and blocked addresses into vectors
    auto allowed_addresses = parse_address_list(allowed_addrs);
    auto blocked_addresses = parse_address_list(blocked_addrs);

    // Initialize logging with debug level if --debug flag is present, otherwise info
    Logger::init(debug_mode ? "debug" : "info");
    
    try {
        auto instances_table = config.get_table("instances");
        if (instances_table.empty()) {
            std::cerr << "Error: Missing 'instances' configuration" << std::endl;
            return false;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: Invalid 'instances' configuration: " << e.what() << std::endl;
        return false;
    }

    auto instances = config.get_table("instances");
    if (instances.empty()) {
        std::cerr << "Error: 'instances' configuration table is empty" << std::endl;
        return false;
    }

    bool valid_config = true;
    for (const auto& [instance_name, instance_data] : instances) {
        // Check if "host_prefix" exists in the instance_data map
        if (instance_data.find("prefix_url") == instance_data.end()) {
            std::cerr << "Error: Instance '" << instance_name << "' is missing required 'host_prefix' field" << std::endl;
            valid_config = false;
        }
    }

    if (!valid_config) {
        std::cerr << "Error: Invalid instance configuration. Exiting." << std::endl;
        return false;
    }

    // Log instance configurations
    for (const auto& [instance_name, instance_data] : instances) {
        std::string host_prefix = instance_data.at("prefix_url");
        Logger::get().info("Instance '{}' configured with host prefix: {}", 
                                  instance_name, host_prefix);
    }

    // Continue with server setup after validation
    try {
        // Create shared components
        auto http_client = create_http_client();
        auto base_store = std::make_shared<FileResourceStore>(data_dir);
        auto private_store = std::make_shared<FileResourceStore>(private_data_dir);
        
        // Create delivery service
        auto delivery_service = std::make_shared<DeliveryService>(
            base_store,
            private_store,
            std::move(http_client),
            false);
            
        // Create LLM responder service if enabled
        std::shared_ptr<LlmResponderService> llm_responder_service;
        if (enable_llm) {
            Logger::get().info("Initializing LLM responder service with Ollama endpoint: {}", ollama_endpoint);
            Logger::get().info("Using Ollama model: {}", ollama_model);
            
            llm_responder_service = std::make_shared<LlmResponderService>(
                base_store,
                private_store,
                delivery_service,
                create_http_client(),
                ollama_endpoint,
                ollama_model);
        }
            
        // Create handlers in reverse order (last to first)
        auto resource_handler = std::make_shared<ResourceHandler>(
            base_store->share(),
            config);
            
        // Initialize ActivityPubHandler with or without LLM responder service
        std::shared_ptr<ActivityPubHandler> activity_handler;
        if (enable_llm && llm_responder_service) {
            activity_handler = std::make_shared<ActivityPubHandler>(
                base_store->share(),
                private_store->share(),
                delivery_service,
                llm_responder_service,
                config);
            Logger::get().info("ActivityPubHandler initialized with LLM responder service and private store");
        } else {
            activity_handler = std::make_shared<ActivityPubHandler>(
                base_store->share(),
                private_store->share(),
                delivery_service,
                config);
            Logger::get().info("ActivityPubHandler initialized with private store");
        }
            
        auto webfinger_handler = std::make_shared<WebFingerHandler>(
            base_store->share(),
            config);
        
        // Set up the chain
        activity_handler->set_successor(resource_handler);
        webfinger_handler->set_successor(activity_handler);
        
        // Log configuration
        Logger::get().info("Starting ActivityPub server on {}:{}", address, port);
        Logger::get().info("Using data directory: {}", data_dir);
        Logger::get().info("Using private data directory: {}", private_data_dir);
        
        // Log network filtering configuration
        if (!blocked_addresses.empty()) {
            std::string blocked_list;
            for (const auto& addr : blocked_addresses) {
                if (!blocked_list.empty()) blocked_list += ", ";
                blocked_list += addr;
            }
            Logger::get().info("Network blocking enabled. Blocked addresses: {}", blocked_list);
        }
        
        if (!allowed_addresses.empty()) {
            std::string allowed_list;
            for (const auto& addr : allowed_addresses) {
                if (!allowed_list.empty()) allowed_list += ", ";
                allowed_list += addr;
            }
            Logger::get().info("Network filtering enabled. Allowed addresses: {}", allowed_list);
        } else {
            Logger::get().info("No explicit allow list - only private addresses will be allowed");
        }
        
        if (debug_mode) {
            Logger::get().debug("Debug logging enabled");
        }
        
        // Create and run server with the first handler in the chain
        Server server{address, port, webfinger_handler, allowed_addresses, blocked_addresses};
        server.run();
        
        return true;
    } catch(const std::exception& e) {
        Logger::get().error("Server terminated with error: {}", e.what());
        return false;
    }
}

bool resource_path_command(const std::string& uri, const Config& config) {
    std::string storage_dir = config.get<std::string>("data.public", "data");
    
    try {
        // Create a resource store
        FileResourceStore store(storage_dir);
        std::string path = store.get_storage_path(uri);
        std::cout << path << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error determining resource path: " << e.what() << std::endl;
        return false;
    }
}

} // namespace jaseur