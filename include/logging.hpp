#pragma once
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <memory>

namespace jaseur {

class Logger {
public:
    static void init(const std::string& log_level = "info", const std::string& file_path = "") {
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        std::vector<spdlog::sink_ptr> sinks{console_sink};
        
        if (!file_path.empty()) {
            auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(file_path, true);
            sinks.push_back(file_sink);
        }
        
        auto logger = std::make_shared<spdlog::logger>("ap_logger", sinks.begin(), sinks.end());
        
        // Set log level
        if (log_level == "debug") {
            logger->set_level(spdlog::level::debug);
        } else if (log_level == "info") {
            logger->set_level(spdlog::level::info);
        } else if (log_level == "warn") {
            logger->set_level(spdlog::level::warn);
        } else if (log_level == "error") {
            logger->set_level(spdlog::level::err);
        }
        
        spdlog::set_default_logger(logger);
        spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%s:%#] %v");
    }
    
    static auto& get() {
        return *spdlog::get("ap_logger");
    }
};

} // namespace jaseur