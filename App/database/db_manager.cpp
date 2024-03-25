#include "db_manager.h"

#include "../libs/toml.hpp"
#include <iostream>
#include <string>
#include <pqxx/pqxx>

namespace db_manager {

    bool create_new_sheme(const std::string& name, size_t threshold, size_t share_count, size_t secret_length, std::string& error_message) {
        
        auto config = toml::parse_file("Settings.toml");
        auto database_connection_string = config["sss_sgx"]["database_connection_string"].as_string()->get();

        try
        {
            pqxx::connection conn(database_connection_string);
            if (conn.is_open()) {

                std::string create_table_query =
                    "CREATE TABLE IF NOT EXISTS sss_scheme ( "
                    "id SERIAL PRIMARY KEY, "
                    "name varchar(100) UNIQUE, "
                    "threshold INTEGER DEFAULT 0,"
                    "share_count INTEGER DEFAULT 0,"
                    "secret_length INTEGER DEFAULT 0,"
                    "sealed_secret BYTEA);";

                pqxx::work txn(conn);
                txn.exec(create_table_query);
                txn.commit();

                std::string insert_command =
                    "INSERT INTO sss_scheme (name, threshold, share_count, secret_length) VALUES ($1, $2, $3, $4);";
                pqxx::work txn2(conn);

                txn2.exec_params(insert_command, name, threshold, share_count, secret_length);
                txn2.commit();

                conn.close();
                return true;
            } else {
                error_message = "Failed to connect to the database!";
                return false;
            }
        }
        catch (std::exception const &e)
        {
            error_message = e.what();
            return false;
        }

        return true;
    } // create_new_sheme

    bool add_sealed_secret(const std::string& name, char* sealed_secret, size_t sealed_secret_size, std::string& error_message) {
    
        auto config = toml::parse_file("Settings.toml");
        auto database_connection_string = config["sss_sgx"]["database_connection_string"].as_string()->get();

        try
        {
            pqxx::connection conn(database_connection_string);
            if (conn.is_open()) {

                std::string update_command =
                    "UPDATE sss_scheme "
                    "SET sealed_secret = $1 "
                    "WHERE name = $2;";
                pqxx::work txn2(conn);

                std::basic_string_view<std::byte> sealed_data_view(reinterpret_cast<std::byte*>(sealed_secret), sealed_secret_size);

                txn2.exec_params(update_command, sealed_data_view, name);
                txn2.commit();

                conn.close();
                return true;
            } else {
                error_message = "Failed to connect to the database!";
                return false;
            }
        }
        catch (std::exception const &e)
        {
            error_message = e.what();
            return false;
        }

        return true;
        
    } // add_sealed_secret

    bool add_sealed_key_share(const std::string& name, char* sealed_key_share, size_t sealed_key_share_size, std::string& error_message) {
        
            auto config = toml::parse_file("Settings.toml");
            auto database_connection_string = config["sss_sgx"]["database_connection_string"].as_string()->get();
    
            try
            {
                pqxx::connection conn(database_connection_string);
                if (conn.is_open()) {

                    std::string create_table_query =
                        "CREATE TABLE IF NOT EXISTS sss_key_share ( "
                        "id SERIAL PRIMARY KEY, "
                        "name varchar(100), "
                        "sealed_key_share BYTEA);";

                    pqxx::work txn(conn);
                    txn.exec(create_table_query);
                    txn.commit();
    
                    std::string insert_command =
                        "INSERT INTO sss_key_share (name, sealed_key_share) VALUES ($1, $2);";

                    pqxx::work txn2(conn);
    
                    std::basic_string_view<std::byte> sealed_data_view(reinterpret_cast<std::byte*>(sealed_key_share), sealed_key_share_size);
    
                    txn2.exec_params(insert_command, name, sealed_data_view);
                    txn2.commit();
    
                    conn.close();
                    return true;
                } else {
                    error_message = "Failed to connect to the database!";
                    return false;
                }
            }
            catch (std::exception const &e)
            {
                error_message = e.what();
                return false;
            }
    
            return true;
    } // add_sealed_key_share

}// namespace db_manager