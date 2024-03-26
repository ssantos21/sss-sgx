#include "db_manager.h"

#include "../libs/toml.hpp"
#include "../utils/utils.h"

#include <iostream>
#include <string>
#include <pqxx/pqxx>
#include <vector>

namespace db_manager {

    bool create_new_scheme(const std::string& name, size_t threshold, size_t share_count, size_t secret_length, std::string& error_message) {
        
        auto config = toml::parse_file("Settings.toml");
        auto database_connection_string = config["sss_sgx"]["database_connection_string"].as_string()->get();

        try
        {
            pqxx::connection conn(database_connection_string);
            if (conn.is_open()) {

                std::string create_table_query =
                    "CREATE TABLE IF NOT EXISTS sss_scheme ( "
                    "id SERIAL PRIMARY KEY, "
                    "name varchar(100) UNIQUE NOT NULL, "
                    "threshold INTEGER DEFAULT 0 NOT NULL,"
                    "share_count INTEGER DEFAULT 0 NOT NULL,"
                    "secret_length INTEGER DEFAULT 0 NOT NULL,"
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

    bool add_sealed_key_share(const std::string& seed_name, char* sealed_key_share, size_t sealed_key_share_size, size_t index, std::string& error_message) {
        
            auto config = toml::parse_file("Settings.toml");
            auto database_connection_string = config["sss_sgx"]["database_connection_string"].as_string()->get();
    
            try
            {
                pqxx::connection conn(database_connection_string);
                if (conn.is_open()) {

                    std::string create_table_query =
                        "CREATE TABLE IF NOT EXISTS sss_key_share ( "
                        "id SERIAL PRIMARY KEY, "
                        "seed_name varchar(100) NOT NULL, "
                        "sealed_key_share BYTEA NOT NULL, "
                        "index INTEGER DEFAULT 0 NOT NULL, "
                        "UNIQUE(seed_name, index));";

                    pqxx::work txn(conn);
                    txn.exec(create_table_query);
                    txn.commit();
    
                    std::string insert_command =
                        "INSERT INTO sss_key_share (seed_name, sealed_key_share, index) VALUES ($1, $2, $3);";

                    pqxx::work txn2(conn);
    
                    std::basic_string_view<std::byte> sealed_data_view(reinterpret_cast<std::byte*>(sealed_key_share), sealed_key_share_size);
    
                    txn2.exec_params(insert_command, seed_name, sealed_data_view, index);
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

    bool get_scheme(std::string& seed_name, std::string& error_message, Scheme& scheme) {

        auto config = toml::parse_file("Settings.toml");
        auto database_connection_string = config["sss_sgx"]["database_connection_string"].as_string()->get();

        try
        {
            pqxx::connection conn(database_connection_string);
            if (conn.is_open()) {
                bool res = false;

                std::string sss_scheme_query =
                    "SELECT threshold, share_count, secret_length, sealed_secret FROM sss_scheme WHERE name = $1;";

                pqxx::nontransaction ntxn(conn);

                conn.prepare("sss_scheme_query", sss_scheme_query);

                pqxx::result result = ntxn.exec_prepared("sss_scheme_query", seed_name);

                if (!result.empty()) {

                    scheme.name = seed_name;
                    scheme.threshold = result[0]["threshold"].as<size_t>();
                    scheme.share_count = result[0]["share_count"].as<size_t>();
                    scheme.secret_length = result[0]["secret_length"].as<size_t>();

                    scheme.sealed_secret_size = utils::sgx_calc_sealed_data_size(0U, (uint32_t) scheme.secret_length);

                    scheme.sealed_secret = new char[scheme.sealed_secret_size];

                    auto sealed_secret_field = result[0]["sealed_secret"];

                    if (!sealed_secret_field.is_null()) {

                        auto sealed_secret_view = sealed_secret_field.as<std::basic_string<std::byte>>();

                        if (sealed_secret_view.size() != scheme.sealed_secret_size) {
                            error_message = "Failed to retrieve keypair. Different size than expected !";
                            return false;
                        }

                        memcpy(scheme.sealed_secret, sealed_secret_view.data(), scheme.sealed_secret_size);
                    } else {
                        memset(scheme.sealed_secret, 0, scheme.sealed_secret_size);
                    }

                    res = true;
                }
                else {
                    error_message = "Failed to retrieve scheme. No data found !";
                }

                conn.close();
                return res;
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

    }

    std::vector<KeyShare> get_key_shares(const Scheme& scheme, std::string& error_message) {
            
            std::vector<KeyShare> key_shares;

            if (scheme.name.empty()) {
                error_message = "Scheme name is empty!";
                return key_shares;
            }

            if (scheme.secret_length == 0) {
                error_message = "Secret length is 0!";
                return key_shares;
            }
    
            auto config = toml::parse_file("Settings.toml");
            auto database_connection_string = config["sss_sgx"]["database_connection_string"].as_string()->get();
    
            try
            {
                pqxx::connection conn(database_connection_string);
                if (conn.is_open()) {
    
                    std::string sss_key_share_query =
                        "SELECT index, sealed_key_share FROM sss_key_share WHERE seed_name = $1;";
    
                    pqxx::nontransaction ntxn(conn);
    
                    conn.prepare("sss_key_share_query", sss_key_share_query);
    
                    pqxx::result result = ntxn.exec_prepared("sss_key_share_query", scheme.name);
    
                    for (auto row : result) {
                        KeyShare key_share;

                        key_share.index = row["index"].as<size_t>();

                        key_share.sealed_data_size = utils::sgx_calc_sealed_data_size(0U, (uint32_t) scheme.secret_length);
                        key_share.sealed_data = new char[key_share.sealed_data_size];
    
                        auto sealed_key_share_field = row["sealed_key_share"];
    
                        if (!sealed_key_share_field.is_null()) {
    
                            auto sealed_key_share_view = sealed_key_share_field.as<std::basic_string<std::byte>>();
    
                            if (sealed_key_share_view.size() != key_share.sealed_data_size) {
                                error_message = "Failed to retrieve keypair. Different size than expected !";
                                return key_shares;
                            }
    
                            memcpy(key_share.sealed_data, sealed_key_share_view.data(), key_share.sealed_data_size);
                        } else {
                            memset(key_share.sealed_data, 0, key_share.sealed_data_size);
                        }
    
                        key_shares.push_back(key_share);
                    }
    
                    conn.close();
                    return key_shares;
                } else {
                    error_message = "Failed to connect to the database!";
                    return key_shares;
                }
            }
            catch (std::exception const &e)
            {
                error_message = e.what();
                return key_shares;
            }
    
            return key_shares;
    }
    

}// namespace db_manager