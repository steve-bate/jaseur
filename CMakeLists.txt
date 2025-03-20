cmake_minimum_required(VERSION 3.16)
# Set policy CMP0135 to NEW to fix timestamp extraction warning
# cmake_policy(SET CMP0135 NEW)

project(jaseur)

# Enable testing
enable_testing()

# Set build type
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

# Compiler flags
add_compile_options(-Wall -Wextra -g -O0)
add_compile_options(-Wno-redundant-move)  # Suppress redundant-move warnings

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(OpenSSL REQUIRED)

# Add subdirectories for dependencies
include(FetchContent)

# Add json dependency
FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz
)
FetchContent_MakeAvailable(json)

# Add TOML11 dependency
FetchContent_Declare(
    toml11
    GIT_REPOSITORY https://github.com/ToruNiina/toml11.git
    GIT_TAG v3.7.1
)
FetchContent_MakeAvailable(toml11)

# Add CLI11 dependency
FetchContent_Declare(
    CLI11
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11
    GIT_TAG v2.3.2
)
FetchContent_MakeAvailable(CLI11)

# Add spdlog dependency
FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG v1.12.0
)
FetchContent_MakeAvailable(spdlog)

# Add googletest dependency
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG release-1.12.1
)
FetchContent_MakeAvailable(googletest)

# Server library
add_library(server_lib
    src/server.cpp
    src/resource_handler.cpp
    src/webfinger_handler.cpp
    src/resource_store.cpp
    src/activitypub_handler.cpp
    src/delivery_service.cpp
    src/http_client.cpp
    src/llm_responder_service.cpp
    src/config.cpp
    src/request_handler.cpp
)

target_include_directories(server_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(server_lib PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    toml11::toml11
    CLI11::CLI11
    nlohmann_json::nlohmann_json
    spdlog::spdlog
)

# Main executable
add_executable(jaseur src/main.cpp)
target_link_libraries(jaseur PRIVATE server_lib)

# Tests executable
add_executable(jaseur_tests
    tests/server_test.cpp
    tests/resource_handler_test.cpp
    tests/webfinger_handler_test.cpp
    tests/activitypub_handler_test.cpp
    tests/delivery_service_test.cpp
    tests/llm_responder_service_test.cpp
)

target_link_libraries(jaseur_tests PRIVATE
    server_lib
    gtest_main
    gmock_main
)

include(GoogleTest)
gtest_discover_tests(jaseur_tests)