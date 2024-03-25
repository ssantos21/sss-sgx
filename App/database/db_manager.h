#pragma once

#ifndef DB_MANAGER_H
#define DB_MANAGER_H

#include <string>

namespace db_manager {
    bool create_new_sheme(const std::string& name, size_t threshold, size_t share_count, size_t secret_length, std::string& error_message);
    bool add_sealed_secret(const std::string& name, char* sealed_secret, size_t sealed_secret_size, std::string& error_message);
} // namespace db_manager

#endif // DB_MANAGER_H