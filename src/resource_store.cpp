#include "resource_store.hpp"
#include <iomanip>
#include <sstream>
#include <iostream>
#include <fstream>
#include <openssl/evp.h>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <random>
#include <regex>

namespace jaseur {

std::string FileResourceStore::compute_hash(const std::string& uri) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context != nullptr) {
        if (EVP_DigestInit_ex(context, EVP_sha256(), nullptr)) {
            if (EVP_DigestUpdate(context, uri.c_str(), uri.size())) {
                if (EVP_DigestFinal_ex(context, hash, &lengthOfHash)) {
                    EVP_MD_CTX_free(context);
                    std::stringstream ss;
                    for (unsigned int i = 0; i < lengthOfHash; ++i) {
                        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
                    }
                    return ss.str();
                }
            }
        }
        EVP_MD_CTX_free(context);
    }
    return "";
}

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

std::string FileResourceStore::generate_uuid() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    static const char* digits = "0123456789abcdef";
    
    std::string uuid(36, '-');
    uuid[8] = '-';
    uuid[13] = '-';
    uuid[18] = '-';
    uuid[23] = '-';
    
    for (int i = 0; i < 36; i++) {
        if (uuid[i] == '-') {
            continue;
        }
        uuid[i] = digits[dis(gen)];
    }
    
    // Set version (4) and variant (8, 9, a, or b)
    uuid[14] = '4';
    uuid[19] = digits[(dis(gen) & 0x3) | 0x8];
    
    return uuid;
}

std::string FileResourceStore::get_storage_path(const std::string& uri, bool for_write) {
    // If we're in hash-only mode, just return the hash
    if (hash_only_mode_) {
        return compute_hash(uri) + ".json";
    }
    
    // Check if we already have a cached path for this URI
    auto cache_it = uri_to_path_cache_.find(uri);
    if (!for_write && cache_it != uri_to_path_cache_.end()) {
        return cache_it->second;
    }
    
    if (for_write) {
        // For new files, create a path with the domain info and a new UUID
        std::string domain = extract_domain_info(uri);
        std::string path = storage_dir_ + "/" + domain;
        
        // Create domain directory if it doesn't exist
        if (!std::filesystem::exists(path)) {
            std::filesystem::create_directories(path);
        }
        
        // Generate UUID-based filename
        std::string uuid = generate_uuid();
        std::string full_path = path + "/" + uuid + ".json";
        
        // Cache this path for future lookups
        uri_to_path_cache_[uri] = full_path;
        return full_path;
    }
    else {
        // For reading, look in the domain-specific directory
        std::string domain = extract_domain_info(uri);
        std::string domain_dir = storage_dir_ + "/" + domain;
        
        // If domain directory exists, search for a file with matching ID field
        if (std::filesystem::exists(domain_dir)) {
            for (const auto& entry : std::filesystem::directory_iterator(domain_dir)) {
                if (entry.path().extension() == ".json") {
                    try {
                        std::ifstream file(entry.path());
                        if (!file.is_open()) {
                            continue;
                        }
                        
                        nlohmann::json data = nlohmann::json::parse(file);
                        file.close();
                        
                        if (data.contains("id") && data["id"].is_string() && 
                            data["id"].get<std::string>() == uri) {
                            // Found the file, cache the path
                            uri_to_path_cache_[uri] = entry.path().string();
                            return entry.path().string();
                        }
                    }
                    catch (const std::exception& e) {
                        // Skip invalid JSON files
                        continue;
                    }
                }
            }
        }
        
        // Not found, generate a new path for potential write
        return get_storage_path(uri, true);
    }
}

bool FileResourceStore::store_json(const std::string& uri, const std::string& json_str) {
    std::string file_path = get_storage_path(uri, true);
    
    std::ofstream file(file_path);
    if (!file.is_open()) {
        std::cerr << "Failed to open file for writing: " << file_path << std::endl;
        return false;
    }
    
    file << json_str;
    file.close();
    return true;
}

std::string FileResourceStore::load_json_str(const std::string& uri) {
    std::string file_path = get_storage_path(uri);
    
    std::ifstream file(file_path);
    if (!file.is_open()) {
        std::cerr << "Failed to open file for reading: " << file_path << std::endl;
        return "{}"; // Return empty JSON object
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();
    return buffer.str();
}

void FileResourceStore::ensure_storage_dir() {
    if (hash_only_mode_) {
        return; // Skip directory creation in hash-only mode
    }
    
    // Create main storage directory if it doesn't exist
    if (!std::filesystem::exists(storage_dir_)) {
        std::filesystem::create_directories(storage_dir_);
    }
}

// ResourceStore interface implementation
nlohmann::json FileResourceStore::get(const std::string& uri) {
    std::string json_str = load_json_str(uri);
    try {
        return nlohmann::json::parse(json_str);
    } catch (const nlohmann::json::parse_error& e) {
        std::cerr << "JSON parse error: " << e.what() << std::endl;
        return nlohmann::json::object(); // Return empty object on failure
    }
}

bool FileResourceStore::exists(const std::string& uri) {
    std::string file_path = get_storage_path(uri);
    return std::filesystem::exists(file_path);
}

bool FileResourceStore::put(const nlohmann::json& json) {
    if (!json.contains("id") || !json["id"].is_string()) {
        std::cerr << "JSON object has no valid 'id' field" << std::endl;
        return false;
    }
    
    std::string uri = json["id"].get<std::string>();
    // Use dump with indentation=2 for pretty formatting
    return store_json(uri, json.dump(2));
}

bool FileResourceStore::remove(const std::string& uri) {
    std::string file_path = get_storage_path(uri);
    
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

std::vector<nlohmann::json> FileResourceStore::query(const Query& query) {
    std::vector<nlohmann::json> results;
    
    try {
        // Iterate through all domain directories in the storage directory
        for (const auto& domain_entry : std::filesystem::directory_iterator(storage_dir_)) {
            if (domain_entry.is_directory()) {
                // Iterate through all files in the domain directory
                for (const auto& file_entry : std::filesystem::directory_iterator(domain_entry.path())) {
                    if (file_entry.path().extension() == ".json") {
                        try {
                            // Load and parse the JSON
                            std::ifstream file(file_entry.path());
                            if (!file.is_open()) {
                                continue;
                            }
                            
                            nlohmann::json data = nlohmann::json::parse(file);
                            file.close();
                            
                            // Check if all query parameters match
                            bool matches = true;
                            for (const auto& [key, value] : query) {
                                if (!data.contains(key)) {
                                    matches = false;
                                    break;
                                }
                                
                                if (data[key].is_string()) {
                                    // For strings, do exact match
                                    if (data[key].get<std::string>() != value) {
                                        matches = false;
                                        break;
                                    }
                                } 
                                else if (data[key].is_array()) {
                                    // For arrays, look for value in the array
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
                                }
                                else {
                                    // For other types, try string comparison (might not work for all cases)
                                    std::string data_str = data[key].dump();
                                    if (data_str != value && data_str != "\"" + value + "\"") {
                                        matches = false;
                                        break;
                                    }
                                }
                            }
                            
                            if (matches) {
                                // If the file matches, add it to results and cache its path
                                if (data.contains("id") && data["id"].is_string()) {
                                    uri_to_path_cache_[data["id"].get<std::string>()] = file_entry.path().string();
                                }
                                results.push_back(std::move(data));
                            }
                        } catch (const std::exception& e) {
                            std::cerr << "Error processing file " << file_entry.path().string() << ": " << e.what() << std::endl;
                        }
                    }
                }
            }
        }
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Filesystem error during query: " << e.what() << std::endl;
    }
    
    return results;
}

} // namespace jaseur