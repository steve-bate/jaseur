#include "config.hpp"
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <filesystem>
#include <algorithm>
#include <CLI/CLI.hpp>

// Declaration for environ
extern char** environ;

namespace fs = std::filesystem;
namespace jaseur {

Config::Config() {
    // Empty constructor
}

void Config::load_from_env() {
    // Iterate through all environment variables
    char** env = environ;
    while (*env) {
        std::string env_var = *env;
        size_t equals_pos = env_var.find('=');
        
        if (equals_pos != std::string::npos) {
            std::string key = env_var.substr(0, equals_pos);
            std::string value = env_var.substr(equals_pos + 1);
            
            // Only process environment variables with AP_ prefix
            if (key.find("AP_") == 0) {
                // Convert AP_VARIABLE_NAME to variable.name
                std::string normalized_key = key.substr(3); // Remove AP_ prefix
                std::transform(normalized_key.begin(), normalized_key.end(), normalized_key.begin(), ::tolower);
                
                std::string processed_key;
                for (char c : normalized_key) {
                    if (c == '_') {
                        processed_key += '.';
                    } else {
                        processed_key += c;
                    }
                }
                
                // Check if value contains commas, indicating a list
                if (value.find(',') != std::string::npos) {
                    std::vector<std::string> values;
                    std::stringstream ss(value);
                    std::string item;
                    
                    while (std::getline(ss, item, ',')) {
                        values.push_back(item);
                    }
                    
                    set_list<std::string>(processed_key, values);
                } else {
                    // Try to parse value as bool
                    if (value == "true" || value == "1") {
                        set<bool>(processed_key, true);
                    } else if (value == "false" || value == "0") {
                        set<bool>(processed_key, false);
                    } else {
                        // Try to parse value as int
                        try {
                            int int_value = std::stoi(value);
                            set<int>(processed_key, int_value);
                        } catch (const std::exception&) {
                            // Default to string
                            set<std::string>(processed_key, value);
                        }
                    }
                }
            }
        }
        env++;
    }
}

void Config::load_from_args(int argc, char* argv[]) {
    CLI::App app{"Jaseur ActivityPub Server"};
    
    // Store unknown options and positionals
    app.allow_extras();
    
    try {
        app.parse(argc, argv);
        
        // Extract all options, including extras
        for (const auto& option : app.remaining()) {
            if (option.size() > 2 && option.substr(0, 2) == "--") {
                std::string key = option.substr(2);
                std::string value;
                
                // Check if option contains an equal sign
                size_t equals_pos = key.find('=');
                if (equals_pos != std::string::npos) {
                    value = key.substr(equals_pos + 1);
                    key = key.substr(0, equals_pos);
                    
                    // Check if value contains commas, indicating a list
                    if (value.find(',') != std::string::npos) {
                        std::vector<std::string> values;
                        std::stringstream ss(value);
                        std::string item;
                        
                        while (std::getline(ss, item, ',')) {
                            values.push_back(item);
                        }
                        
                        set_list<std::string>(key, values);
                    } else {
                        // Try to parse value as bool
                        if (value == "true") {
                            set<bool>(key, true);
                        } else if (value == "false") {
                            set<bool>(key, false);
                        } else {
                            // Try to parse value as int
                            try {
                                int int_value = std::stoi(value);
                                set<int>(key, int_value);
                            } catch (const std::exception&) {
                                // Default to string
                                set<std::string>(key, value);
                            }
                        }
                    }
                } else {
                    // Boolean flag (--flag with no value is treated as true)
                    set<bool>(key, true);
                }
            }
        }
    } catch (const CLI::ParseError& e) {
        // Ignore parse errors, as we're just extracting arguments
    }
}

bool Config::load_from_toml(const std::string& file_path) {
    try {
        if (fs::exists(file_path)) {
            auto data = toml::parse(file_path);
            load_nested_toml(data);
            return true;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error loading TOML configuration: " << e.what() << std::endl;
    }
    return false;
}

void Config::load_nested_toml(const toml::value& toml_value, const std::string& prefix) {
    // Process table fields
    if (toml_value.is_table()) {
        for (const auto& [key, value] : toml_value.as_table()) {
            std::string full_key = prefix.empty() ? key : prefix + "." + key;
            
            if (value.is_table()) {
                // Check if this is a special case for instances with inner tables
                if (full_key == "instances" || prefix == "instances") {
                    // Handle the multi-tenant instances configuration
                    if (full_key == "instances") {
                        // This is the root instances table
                        ConfigTable instances_table;
                        
                        // Process each instance (which is a nested table)
                        for (const auto& [instance_name, instance_config] : value.as_table()) {
                            if (instance_config.is_table()) {
                                std::map<std::string, std::string> instance_map;
                                
                                // Process each property in the instance config
                                for (const auto& [prop_key, prop_value] : instance_config.as_table()) {
                                    if (prop_value.is_string()) {
                                        instance_map[prop_key] = prop_value.as_string();
                                    }
                                }
                                
                                instances_table[instance_name] = instance_map;
                            }
                        }
                        
                        set_table("instances", instances_table);
                    } else {
                        // This is an individual instance in the table
                        // We'll handle it at the instances root level
                        load_nested_toml(value, full_key);
                    }
                } else {
                    // Recursively process regular nested tables
                    load_nested_toml(value, full_key);
                }
            } else if (value.is_array()) {
                const auto& array = value.as_array();
                if (!array.empty()) {
                    if (array.front().is_string()) {
                        std::vector<std::string> str_values;
                        for (const auto& item : array) {
                            str_values.push_back(item.as_string());
                        }
                        set_list<std::string>(full_key, str_values);
                    } else if (array.front().is_integer()) {
                        std::vector<int> int_values;
                        for (const auto& item : array) {
                            int_values.push_back(item.as_integer());
                        }
                        set_list<int>(full_key, int_values);
                    } else if (array.front().is_boolean()) {
                        std::vector<bool> bool_values;
                        for (const auto& item : array) {
                            bool_values.push_back(item.as_boolean());
                        }
                        set_list<bool>(full_key, bool_values);
                    }
                }
            } else if (value.is_string()) {
                set<std::string>(full_key, value.as_string());
            } else if (value.is_integer()) {
                set<int>(full_key, value.as_integer());
            } else if (value.is_boolean()) {
                set<bool>(full_key, value.as_boolean());
            }
        }
    }
}

std::vector<std::string> Config::split_key(const std::string& key) const {
    std::vector<std::string> parts;
    std::stringstream ss(key);
    std::string part;
    
    while (std::getline(ss, part, '.')) {
        parts.push_back(part);
    }
    
    return parts;
}

template<typename T>
std::optional<T> Config::get_value(const std::string& key) const {
    auto it = config_values_.find(key);
    if (it != config_values_.end()) {
        try {
            return std::get<T>(it->second);
        } catch (const std::bad_variant_access&) {
            // Type mismatch
            return std::nullopt;
        }
    }
    return std::nullopt;
}

template<typename T>
std::optional<T> Config::get(const std::string& key) const {
    return get_value<T>(key);
}

template<typename T>
T Config::get(const std::string& key, const T& default_value) const {
    auto value = get<T>(key);
    return value.value_or(default_value);
}

template<typename T>
std::vector<T> Config::get_list(const std::string& key) const {
    auto value = get_value<std::vector<T>>(key);
    return value.value_or(std::vector<T>());
}

template<typename T>
std::vector<T> Config::get_list(const std::string& key, const std::vector<T>& default_value) const {
    auto value = get_list<T>(key);
    return value.empty() ? default_value : value;
}

template<typename T>
void Config::set(const std::string& key, const T& value) {
    config_values_[key] = value;
}

template<typename T>
void Config::set_list(const std::string& key, const std::vector<T>& values) {
    config_values_[key] = values;
}

// Implement the new table methods
Config::ConfigTable Config::get_table(const std::string& key) const {
    auto value = get_value<ConfigTable>(key);
    return value.value_or(ConfigTable{});
}

Config::ConfigTable Config::get_table(const std::string& key, const ConfigTable& default_value) const {
    auto value = get_table(key);
    return value.empty() ? default_value : value;
}

void Config::set_table(const std::string& key, const ConfigTable& table) {
    config_values_[key] = table;
}

bool Config::has(const std::string& key) const {
    return config_values_.find(key) != config_values_.end();
}

nlohmann::json Config::to_json() const {
    nlohmann::json result;
    
    for (const auto& [key, value] : config_values_) {
        std::vector<std::string> parts = split_key(key);
        
        nlohmann::json* current = &result;
        for (size_t i = 0; i < parts.size() - 1; ++i) {
            if (!current->contains(parts[i])) {
                (*current)[parts[i]] = nlohmann::json::object();
            }
            current = &(*current)[parts[i]];
        }
        
        const std::string& last_part = parts.back();
        
        std::visit([&](const auto& v) {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, std::string> || 
                         std::is_same_v<T, int> || 
                         std::is_same_v<T, bool> ||
                         std::is_same_v<T, std::vector<std::string>> ||
                         std::is_same_v<T, std::vector<int>> ||
                         std::is_same_v<T, std::vector<bool>>) {
                (*current)[last_part] = v;
            } else if constexpr (std::is_same_v<T, Config::ConfigTable>) {
                // Convert ConfigTable to JSON
                auto& table_json = (*current)[last_part];
                table_json = nlohmann::json::object();
                
                for (const auto& [instance_name, instance_props] : v) {
                    table_json[instance_name] = nlohmann::json::object();
                    for (const auto& [prop_key, prop_value] : instance_props) {
                        table_json[instance_name][prop_key] = prop_value;
                    }
                }
            }
        }, value);
    }
    
    return result;
}

// Template instantiations for common types
template std::optional<std::string> Config::get<std::string>(const std::string&) const;
template std::optional<int> Config::get<int>(const std::string&) const;
template std::optional<bool> Config::get<bool>(const std::string&) const;
template std::string Config::get<std::string>(const std::string&, const std::string&) const;
template int Config::get<int>(const std::string&, const int&) const;
template bool Config::get<bool>(const std::string&, const bool&) const;
template std::vector<std::string> Config::get_list<std::string>(const std::string&) const;
template std::vector<int> Config::get_list<int>(const std::string&) const;
template std::vector<bool> Config::get_list<bool>(const std::string&) const;
template std::vector<std::string> Config::get_list<std::string>(const std::string&, const std::vector<std::string>&) const;
template std::vector<int> Config::get_list<int>(const std::string&, const std::vector<int>&) const;
template std::vector<bool> Config::get_list<bool>(const std::string&, const std::vector<bool>&) const;
template void Config::set<std::string>(const std::string&, const std::string&);
template void Config::set<int>(const std::string&, const int&);
template void Config::set<bool>(const std::string&, const bool&);
template void Config::set_list<std::string>(const std::string&, const std::vector<std::string>&);
template void Config::set_list<int>(const std::string&, const std::vector<int>&);
template void Config::set_list<bool>(const std::string&, const std::vector<bool>&);

} // namespace jaseur