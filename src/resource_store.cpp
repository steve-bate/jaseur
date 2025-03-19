#include "resource_store.hpp"
#include <iomanip>
#include <sstream>
#include <iostream>
#include <fstream>
#include <openssl/evp.h>
#include <nlohmann/json.hpp>
#include <filesystem>

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

std::string FileResourceStore::get_storage_path(const std::string& hash) {
        if (hash_only_mode_) {
            return hash + ".json"; // Return just the filename in hash-only mode
        }
        return storage_dir_ + "/" + hash + ".json";
    }

bool FileResourceStore::store_json(const std::string& uri, const std::string& json_str) {
    std::string hash = compute_hash(uri);
    std::string file_path = get_storage_path(hash);
    
    std::ofstream file(file_path);
    if (!file) {
        std::cerr << "Failed to open file for writing: " << file_path << std::endl;
        return false;
    }
    
    file << json_str;
    return file.good();
}

std::string FileResourceStore::load_json_str(const std::string& uri) {
    std::string hash = compute_hash(uri);
    std::string file_path = get_storage_path(hash);
    
    std::ifstream file(file_path);
    if (!file) {
        std::cerr << "Failed to open file for reading: " << file_path << std::endl;
        return "{}"; // Return empty JSON object
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

void FileResourceStore::ensure_storage_dir() {
        if (hash_only_mode_) {
            return; // Skip directory creation in hash-only mode
        }
        if (!std::filesystem::exists(storage_dir_)) {
            std::filesystem::create_directory(storage_dir_);
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
    std::string hash = compute_hash(uri);
    std::string file_path = get_storage_path(hash);
    return std::filesystem::exists(file_path);
}

bool FileResourceStore::put(const nlohmann::json& json) {
    if (!json.contains("id")) {
        std::cerr << "JSON object has no 'id' field" << std::endl;
        return false;
    }
    
    std::string uri = json["id"].get<std::string>();
    // Use dump with indentation=2 for pretty formatting
    return store_json(uri, json.dump(2));
}

bool FileResourceStore::remove(const std::string& uri) {
    if (!exists(uri)) {
        return false;
    }
    
    std::string hash = compute_hash(uri);
    std::string file_path = get_storage_path(hash);
    
    try {
        return std::filesystem::remove(file_path);
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Failed to remove file: " << e.what() << std::endl;
        return false;
    }
}

std::vector<nlohmann::json> FileResourceStore::query(const Query& query) {
    std::vector<nlohmann::json> results;
    
    // Scan through all files in the directory
    for (const auto& entry : std::filesystem::directory_iterator(storage_dir_)) {
        if (entry.path().extension() == ".json") {
            try {
                // Load and parse the JSON
                std::ifstream file(entry.path());
                nlohmann::json data = nlohmann::json::parse(file);
                
                // Check if all query parameters match
                bool matches = true;
                for (const auto& [key, value] : query) {
                    if (!data.contains(key)) {
                        matches = false;
                        break;
                    }
                    
                    if (data[key].is_string()) {
                        // For strings, do exact match
                        if (data[key] != value) {
                            matches = false;
                            break;
                        }
                    } 
                    else if (data[key].is_array()) {
                        // For arrays, look for value in the array
                        bool found = false;
                        for (const auto& item : data[key]) {
                            if (item.is_string() && item == value) {
                                found = true;
                                break;
                            }
                        }
                        if (!found) {
                            matches = false;
                            break;
                        }
                    }
                    else if (data[key] != value) {
                        // For other types, do direct comparison
                        matches = false;
                        break;
                    }
                }
                
                if (matches) {
                    results.push_back(data);
                }
            } catch (const std::exception& e) {
                std::cerr << "Error processing file " << entry.path().string() << ": " << e.what() << std::endl;
            }
        }
    }
    
    return results;
}

} // namespace jaseur