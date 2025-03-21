#pragma once
#include <string>
#include <filesystem>
#include <vector>
#include <map>
#include <memory>
#include <nlohmann/json.hpp>
namespace jaseur {

// Simple query structure for resource filtering
using Query = std::map<std::string, std::string>;

class ResourceStore {
public:
    virtual ~ResourceStore() = default;
    
    // Core interface methods
    virtual nlohmann::json get(const std::string& uri) = 0;
    virtual bool exists(const std::string& uri) = 0;
    virtual bool put(const nlohmann::json& json) = 0;
    virtual bool remove(const std::string& uri) = 0;
    virtual std::vector<nlohmann::json> query(const Query& query) = 0;

    // Create a new instance that shares the same underlying storage
    virtual std::unique_ptr<ResourceStore> share() = 0;
};

// FileResourceStore implementation that uses filesystem storage
class FileResourceStore : public ResourceStore {
public:
    explicit FileResourceStore(std::string storage_dir = "data")
        : storage_dir_(std::move(storage_dir)) {
            if (!std::filesystem::exists(storage_dir_)) {
                throw std::runtime_error("Storage directory does not exist: " + storage_dir_);
            }
        }
    ~FileResourceStore() override = default;
    
    // ResourceStore interface implementation
    nlohmann::json get(const std::string& uri) override;
    bool exists(const std::string& uri) override;
    bool put(const nlohmann::json& json) override;
    bool remove(const std::string& uri) override;
    std::vector<nlohmann::json> query(const Query& query) override;
    
    // Create a new FileResourceStore that shares the same storage directory
    std::unique_ptr<ResourceStore> share() override {
        return std::make_unique<FileResourceStore>(storage_dir_);
    }
    
    // Helper methods
    std::string extract_domain_info(const std::string& uri);
    std::string extract_url_path(const std::string& uri);
    std::string get_storage_path(const std::string& uri, bool for_write = false);
    
    // Storage directory management
    const std::string& get_storage_dir() const { return storage_dir_; }
    
    void set_storage_dir(std::string dir) { 
        storage_dir_ = std::move(dir);
        if (!std::filesystem::exists(storage_dir_)) {
            throw std::runtime_error("Storage directory does not exist: " + storage_dir_);
        }
    }
    
private:
    bool put_string(const std::string& uri, const std::string& json_str);
    std::string get_string(const std::string& uri);
    std::vector<nlohmann::json> query_prefix(const std::filesystem::path& domain_path, const Query& query);
    std::string storage_dir_;
    
    // Maps URIs to their storage paths for faster lookups
    std::map<std::string, std::string> uri_to_path_cache_;
};

} // namespace jaseur