#include "resource_store.hpp"
#include <iomanip>
#include <sstream>
#include <iostream>
#include <fstream>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <regex>

namespace jaseur {

std::string FileResourceStore::extract_domain_info(const std::string& uri) {
    try {
        // Handle empty URIs
        if (uri.empty()) {
            return "unknown";
        }

        // Add scheme if missing
        std::string full_uri = uri;
        if (uri.find("://") == std::string::npos) {
            full_uri = "https://" + uri;
        }
        
        // Parse the URI
        std::regex uri_regex("^(https?://)?([^/:]+)(:[0-9]+)?(.*)$");
        std::smatch matches;
        
        if (!std::regex_match(full_uri, matches, uri_regex)) {
            return "unknown";
        }
        
        std::string scheme = matches[1].length() > 0 ? 
            matches[1].str().substr(0, matches[1].length() - 3) : "https";
        std::string domain = matches[2].str();
        std::string port = matches[3].length() > 0 ? matches[3].str().substr(1) : "";
        
        // For https with default port or no port, just use domain
        if (scheme == "https" && (port.empty() || port == "443")) {
            return domain;
        }
        
        // For http with default port, prefix with http_
        if (scheme == "http" && (port.empty() || port == "80")) {
            return "http_" + domain;
        }
        
        // For other schemes or non-standard ports, include both
        return scheme + "_" + domain + (port.empty() ? "" : "_" + port);
    } 
    catch (const std::exception& e) {
        std::cerr << "Error parsing URI " << uri << ": " << e.what() << std::endl;
        return "unknown";
    }
}

std::string FileResourceStore::extract_url_path(const std::string& uri) {
    try {
        // Handle empty URIs
        if (uri.empty()) {
            return "";
        }

        // Add scheme if missing
        std::string full_uri = uri;
        if (uri.find("://") == std::string::npos) {
            full_uri = "https://" + uri;
        }
        
        // Parse the URI to extract the path
        std::regex uri_regex("^(https?://)?([^/:]+)(:[0-9]+)?(/.*)?$");
        std::smatch matches;
        
        if (!std::regex_match(full_uri, matches, uri_regex)) {
            return "";
        }
        
        // Extract the path part
        std::string path = matches[4].str();
        
        // If path is empty or just a slash, use "index"
        if (path.empty() || path == "/") {
            return "index";
        }
        
        // Remove leading slash
        if (path[0] == '/') {
            path = path.substr(1);
        }
        
        // Remove query parameters
        size_t question_pos = path.find('?');
        if (question_pos != std::string::npos) {
            path = path.substr(0, question_pos);
        }
        
        // Remove fragment
        size_t hash_pos = path.find('#');
        if (hash_pos != std::string::npos) {
            path = path.substr(0, hash_pos);
        }
        
        // Replace special characters with underscores for filesystem safety
        std::regex unsafe_chars("[^a-zA-Z0-9_/.\\-]");
        path = std::regex_replace(path, unsafe_chars, "_");
        
        return path;
    } 
    catch (const std::exception& e) {
        std::cerr << "Error extracting path from URI " << uri << ": " << e.what() << std::endl;
        return "";
    }
}

std::string FileResourceStore::get_storage_path(const std::string& uri, bool for_write) {
    // Check if we already have a cached path for this URI
    auto cache_it = uri_to_path_cache_.find(uri);
    if (cache_it != uri_to_path_cache_.end()) {
        return cache_it->second;
    }
    
    // Start with the domain-based directory structure
    std::string domain = extract_domain_info(uri);
    std::string base_path = storage_dir_ + "/" + domain;
    
    // Extract the URL path
    std::string url_path = extract_url_path(uri);
    
    // Determine the filename and directory structure
    std::string file_path;
    std::string filename;
    
    if (url_path.empty()) {
        // If no path, just use domain directory and a default name
        file_path = base_path;
        filename = "index.json";
    } else {
        // Split the URL path into directory components and filename
        size_t last_slash = url_path.find_last_of('/');
        
        if (last_slash == std::string::npos) {
            // No subdirectories
            file_path = base_path;
            filename = url_path + ".json";
        } else {
            // Create subdirectories based on URL path
            std::string path_dirs = url_path.substr(0, last_slash);
            std::string last_segment = url_path.substr(last_slash + 1);
            
            file_path = base_path + "/" + path_dirs;
            filename = last_segment.empty() ? "index.json" : last_segment + ".json";
        }
    }
    
    // Create directories only when writing
    if (for_write) {
        std::filesystem::create_directories(file_path);
    }
    
    // Create the full path
    std::string full_path = file_path + "/" + filename;
    
    // Cache this path for future lookups
    uri_to_path_cache_[uri] = full_path;
    return full_path;
}

bool FileResourceStore::put_string(const std::string& uri, const std::string& json_str) {
    std::string file_path = get_storage_path(uri, true);
    
    std::ofstream file(file_path);
    if (!file.is_open()) {
        return false;
    }
    
    file << json_str;
    file.close();
    return true;
}

std::string FileResourceStore::get_string(const std::string& uri) {
    std::string file_path = get_storage_path(uri, false);
    
    std::ifstream file(file_path);
    if (!file.is_open()) {
        return "{}"; // Return empty JSON object
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();
    return buffer.str();
}

// ResourceStore interface implementation
nlohmann::json FileResourceStore::get(const std::string& uri) {
    std::string json_str = get_string(uri);
    try {
        return nlohmann::json::parse(json_str);
    } catch (const nlohmann::json::parse_error& e) {
        std::cerr << "JSON parse error: " << e.what() << std::endl;
        return nlohmann::json::object(); // Return empty object on failure
    }
}

bool FileResourceStore::exists(const std::string& uri) {
    std::string file_path = get_storage_path(uri, false);
    return std::filesystem::exists(file_path);
}

bool FileResourceStore::put(const nlohmann::json& json) {
    if (!json.contains("id") || !json["id"].is_string()) {
        std::cerr << "JSON object has no valid 'id' field" << std::endl;
        return false;
    }
    
    std::string uri = json["id"].get<std::string>();
    // Use dump with indentation=2 for pretty formatting
    return put_string(uri, json.dump(2));
}

bool FileResourceStore::remove(const std::string& uri) {
    std::string file_path = get_storage_path(uri, false);
    
    try {
        if (!std::filesystem::exists(file_path)) {
            return false;
        }
        
        // Remove the cached path
        uri_to_path_cache_.erase(uri);
        return std::filesystem::remove(file_path);
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Failed to remove file: " << e.what() << std::endl;
        return false;
    }
}

std::vector<nlohmann::json> FileResourceStore::query_prefix(const std::filesystem::path& domain_path, const Query& query) {
    std::vector<nlohmann::json> results;
    
    if (!std::filesystem::exists(domain_path)) {
        return results;
    }
    
    try {
        for (const auto& file_entry : std::filesystem::recursive_directory_iterator(domain_path)) {
            if (file_entry.path().extension() == ".json") {
                try {
                    std::ifstream file(file_entry.path());
                    if (!file.is_open()) {
                        continue;
                    }
                    
                    nlohmann::json data = nlohmann::json::parse(file);
                    file.close();
                    
                    bool matches = true;
                    for (const auto& [key, value] : query) {
                        if (!data.contains(key)) {
                            matches = false;
                            break;
                        }
                        
                        if (data[key].is_string()) { // matching based on the field type
                            if (data[key].get<std::string>() != value) {
                                matches = false; // exact match
                                break;
                            }
                        } else if (data[key].is_array()) {
                            bool found = false;
                            for (const auto& item : data[key]) {
                                if (item.is_string() && item.get<std::string>() == value) {
                                    found = true;
                                    break;
                                }
                            }
                            if (!found) {
                                matches = false;
                                break;
                            }
                        } else if (data[key].is_number()) {
                            try {
                                double query_num = std::stod(value);
                                if (std::abs(data[key].get<double>() - query_num) > 1e-10) {
                                    matches = false;
                                    break;
                                }
                            } catch (const std::exception&) {
                                matches = false;
                                break;
                            }
                        } else {
                            std::string data_str = data[key].dump();
                            if (data_str != value && data_str != "\"" + value + "\"") {
                                matches = false;
                                break;
                            }
                        }
                    }
                    
                    if (matches && data.contains("id") && data["id"].is_string()) {
                        uri_to_path_cache_[data["id"].get<std::string>()] = file_entry.path().string();
                        results.push_back(std::move(data));
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Error processing file " << file_entry.path().string() 
                             << ": " << e.what() << std::endl;
                }
            }
        }
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Error reading directory " << domain_path.string() 
                  << ": " << e.what() << std::endl;
    }
    
    return results;
}

std::vector<nlohmann::json> FileResourceStore::query(const Query& query) {
    std::vector<nlohmann::json> results;
    
    try {
        // Check if storage directory exists
        if (!std::filesystem::exists(storage_dir_)) {
            return results;
        }
        
        // Extract and remove @prefix if present
        std::string prefix;
        Query filtered_query;
        
        for (const auto& [key, value] : query) {
            if (key == "@prefix") {
                prefix = value;
            } else {
                filtered_query[key] = value;
            }
        }
        
        // If we have a prefix, search only that domain
        if (!prefix.empty()) {
            try {
                std::string domain = extract_domain_info(prefix);
                if (domain != "unknown") {
                    std::filesystem::path domain_path = storage_dir_ + "/" + domain;
                    auto domain_results = query_prefix(domain_path, filtered_query);
                    results.insert(results.end(), 
                                 std::make_move_iterator(domain_results.begin()),
                                 std::make_move_iterator(domain_results.end()));
                }
            } catch (const std::exception& e) {
                std::cerr << "Error processing prefix " << prefix << ": " << e.what() << std::endl;
            }
        } else {
            // No prefix, search all domains
            for (const auto& domain_entry : std::filesystem::directory_iterator(storage_dir_)) {
                if (domain_entry.is_directory()) {
                    auto domain_results = query_prefix(domain_entry.path(), filtered_query);
                    results.insert(results.end(), 
                                 std::make_move_iterator(domain_results.begin()),
                                 std::make_move_iterator(domain_results.end()));
                }
            }
        }
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Filesystem error during query: " << e.what() << std::endl;
    }
    
    return results;
}

} // namespace jaseur