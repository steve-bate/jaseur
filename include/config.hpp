#pragma once
#include <string>
#include <map>
#include <vector>
#include <filesystem>
#include <variant>
#include <optional>
#include <nlohmann/json.hpp>
// Disable warning about redundant moves in toml11
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wredundant-move"
#include <toml.hpp>
#pragma GCC diagnostic pop

namespace jaseur {

// Version information
constexpr const char* VERSION = "0.4.0";
constexpr const char* SERVER_NAME = "Jaseur";

class Config {
public:
    // Forward declare the ConfigTable type
    using ConfigTable = std::map<std::string, std::map<std::string, std::string>>;
    
    using ConfigValue = std::variant<
        std::string,
        int,
        bool,
        std::vector<std::string>,
        std::vector<int>,
        std::vector<bool>,
        ConfigTable
    >;

    Config();

    // Load configuration from different sources
    void load_from_env();
    void load_from_args(int argc, char* argv[]);
    bool load_from_toml(const std::string& file_path = "jaseur.toml");

    // Get configuration values
    template<typename T>
    std::optional<T> get(const std::string& key) const;
    
    template<typename T>
    T get(const std::string& key, const T& default_value) const;
    
    template<typename T>
    std::vector<T> get_list(const std::string& key) const;
    
    template<typename T>
    std::vector<T> get_list(const std::string& key, const std::vector<T>& default_value) const;

    // Get table configuration
    ConfigTable get_table(const std::string& key) const;
    ConfigTable get_table(const std::string& key, const ConfigTable& default_value) const;

    // Set configuration values
    template<typename T>
    void set(const std::string& key, const T& value);
    
    template<typename T>
    void set_list(const std::string& key, const std::vector<T>& values);

    // Set table configuration
    void set_table(const std::string& key, const ConfigTable& table);

    // Check if a key exists
    bool has(const std::string& key) const;

    // Dump configuration as JSON
    nlohmann::json to_json() const;

private:
    std::map<std::string, ConfigValue> config_values_;
    
    // Helper methods
    std::vector<std::string> split_key(const std::string& key) const;
    void load_nested_toml(const toml::value& toml_value, const std::string& prefix = "");
    
    // Get value from nested structure
    template<typename T>
    std::optional<T> get_value(const std::string& key) const;
};

} // namespace jaseur