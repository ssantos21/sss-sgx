#pragma once

#ifndef DB_MANAGER_H
#define DB_MANAGER_H

#include <string>
#include <vector>

namespace db_manager {

    struct Scheme {
        std::string name;
        size_t threshold;
        size_t share_count;
        size_t secret_length;
        char* sealed_secret;
        size_t sealed_secret_size;
    };

    struct KeyShare {
        size_t index;
        char* sealed_data;
        size_t sealed_data_size;
    };

    bool create_new_scheme(const std::string& name, size_t threshold, size_t share_count, size_t secret_length, std::string& error_message);
    bool add_sealed_secret(const std::string& name, char* sealed_secret, size_t sealed_secret_size, std::string& error_message);
    bool add_sealed_key_share(const std::string& seed_name, char* sealed_key_share, size_t sealed_key_share_size, size_t index, std::string& error_message);
    bool get_scheme(std::string& seed_name, std::string& error_message, Scheme& scheme);
    std::vector<KeyShare> get_key_shares(const Scheme& scheme, std::string& error_message);
} // namespace db_manager

#endif // DB_MANAGER_H