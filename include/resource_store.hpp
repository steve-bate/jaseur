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
    explicit FileResourceStore(std::string storage_dir = "data", bool hash_only_mode = false)
        : storage_dir_(std::move(storage_dir)), hash_only_mode_(hash_only_mode) {
            if (!hash_only_mode_) {
                ensure_storage_dir();
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
    std::string compute_hash(const std::string& uri);
    std::string get_storage_path(const std::string& hash);
    bool store_json(const std::string& uri, const std::string& json_str);
    std::string load_json_str(const std::string& uri);
    void ensure_storage_dir();
    
    // Storage directory management
    const std::string& get_storage_dir() const { return storage_dir_; }
    void set_storage_dir(std::string dir) { 
        storage_dir_ = std::move(dir);
        ensure_storage_dir();
    }
    
private:
    std::string storage_dir_;
    bool hash_only_mode_ = false;
};

} // namespace jaseur