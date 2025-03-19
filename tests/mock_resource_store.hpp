#pragma once

#include "resource_store.hpp"
#include <map>
#include <string>
#include <nlohmann/json.hpp>

namespace jaseur {
namespace test {

// Mock resource store for testing
class MockResourceStore : public ResourceStore {
public:
    // ResourceStore interface implementation
    nlohmann::json get(const std::string& uri) override {
        auto it = resources_.find(uri);
        if (it != resources_.end()) {
            return it->second;
        }
        return nlohmann::json();
    }
    
    bool exists(const std::string& uri) override {
        return resources_.find(uri) != resources_.end();
    }
    
    bool put(const nlohmann::json& json) override {
        // Use the "id" field as the URI
        if (json.contains("id") && json["id"].is_string()) {
            resources_[json["id"].get<std::string>()] = json;
            return true;
        }
        return false;
    }
    
    bool remove(const std::string& uri) override {
        auto it = resources_.find(uri);
        if (it != resources_.end()) {
            resources_.erase(it);
            return true;
        }
        return false;
    }
    
    std::vector<nlohmann::json> query(const Query& query) override {
        std::vector<nlohmann::json> results;
        
        for (const auto& [uri, resource] : resources_) {
            bool match = true;
            
            for (const auto& [key, value] : query) {
                if (!resource.contains(key) || resource[key] != value) {
                    match = false;
                    break;
                }
            }
            
            if (match) {
                results.push_back(resource);
            }
        }
        
        return results;
    }
    
    // Helper methods
    void add_resource(const std::string& uri, const nlohmann::json& resource) {
        resources_[uri] = resource;
    }
    
    void clear() {
        resources_.clear();
    }
    
    const std::map<std::string, nlohmann::json>& resources() const {
        return resources_;
    }
    
    // Share this store's resources with a new instance
    std::unique_ptr<ResourceStore> share() override {
        auto new_store = std::make_unique<MockResourceStore>();
        new_store->resources_ = resources_;  // Share the same data
        return new_store;
    }
    
private:
    std::map<std::string, nlohmann::json> resources_;
};

} // namespace test
} // namespace jaseur