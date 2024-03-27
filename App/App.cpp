#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# define ENCLAVE_FILENAME "enclave.signed.so"

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#include "libs/CLI11.hpp"
#include "libs/toml.hpp"
#include "database/db_manager.h"
#include "utils/utils.h"

#include <mutex>
#include <iostream>
#include <iomanip>
#include <vector>

#include <bc-bip39/bc-bip39.h>
#include <bc-shamir/bc-shamir.h>

#include <pqxx/pqxx>

sgx_enclave_id_t global_eid = 0;

std::string key_to_string(const unsigned char* key, size_t keylen) {
    std::stringstream sb;
    sb << "0x";
    for (int i = 0; i < keylen; i++)
        sb << std::hex << std::setw(2) << std::setfill('0') << (int)key[i];
    return sb.str();
}

/* ocall functions (untrusted) */
void ocall_wait_keyinput(const char *str)
{
    printf("%s", str);
    getchar();
}

/* ocall functions (untrusted) */
void ocall_print_string(const char *str)
{
    printf("%s\n", str);
}

void ocall_print_int(const char *str, const int *number)
{
    printf("%s%d\n", str, *number);
}

void ocall_print_hex(const unsigned char** key, const int *keylen)
{
    printf("%s\n", key_to_string(*key, *keylen).c_str());
}

void ocall_print_bip39(const unsigned char** secret, const int *secret_len)
{
    /// printf("%s\n", key_to_string(*key, *keylen).c_str());

    size_t max_mnemonics_len = 300;
    char mnemonics[max_mnemonics_len];
    size_t mnemonics_len = bip39_mnemonics_from_secret(*secret, *secret_len, mnemonics, max_mnemonics_len);
    // printf("mnemonics_len %d\n", mnemonics_len);
    printf("%s\n", mnemonics);
}

void create_new_scheme(
    sgx_enclave_id_t &enclave_id,
    std::mutex &mutex_enclave_id,
    std::string& seedName,
    size_t threshold,
    size_t shareCount,
    bool generate_seed
    ) {

    const std::lock_guard<std::mutex> lock(mutex_enclave_id);

    size_t secretLen = 32;

    std::string error_message;
    bool res = db_manager::create_new_scheme(seedName, threshold, shareCount, secretLen, error_message);

    if (!res) {
        std::cout << "Database error: " << error_message << std::endl;
        return;
    }

    if (!generate_seed) {
        std::cout << "Scheme created, seed not generated." << std::endl;
        return;
    }

    size_t sealedSecretSize = utils::sgx_calc_sealed_data_size(0U, secretLen);
    char sealedSecret[sealedSecretSize];

    memset(sealedSecret, 0, sealedSecretSize);

    const size_t sealedTotalShareSize = sealedSecretSize * shareCount;
    char sealedShares[sealedTotalShareSize];

    sgx_status_t ecall_ret;
    sgx_status_t status = generate_new_secret(
        enclave_id, &ecall_ret, 
        threshold, shareCount, secretLen,
        sealedSecret, sealedSecretSize,
        sealedShares, sealedTotalShareSize);

    if (ecall_ret != SGX_SUCCESS) {
        std::cout << "Key aggregation Ecall failed " << std::endl;
        return;
    }  if (status != SGX_SUCCESS) {
        std::cout << "Key aggregation failed " << std::endl;
        return;
    }

    res = db_manager::add_sealed_secret(seedName, sealedSecret, sealedSecretSize, error_message);

    if (!res) {
        std::cout << "Database error: " << error_message << std::endl;
        return;
    }

    for (size_t i = 0; i < shareCount; ++i) {

        char sealed_key_share[sealedSecretSize];
        memcpy(sealed_key_share, sealedShares + i * sealedSecretSize, sealedSecretSize);

        res = db_manager::add_sealed_key_share(seedName, sealed_key_share, sealedSecretSize, i, error_message);

        if (!res) {
            std::cout << "Database error: " << error_message << std::endl;
            return;
        }
    }

    // print each element of arrays vector
    /* for (size_t i = 0; i < arrays.size(); ++i) {
        std::cout << "Share " << i << ": " << key_to_string((const unsigned char*) arrays[i].data(), sealedSecretSize) << std::endl;
    }
    */

    std::cout << "Scheme created, seed generated." << std::endl;
    
}

void recover_seed(sgx_enclave_id_t &enclave_id, std::vector<db_manager::KeyShare> &key_shares, db_manager::Scheme &scheme, bool save_seed) {
    
    // Calculate the total size needed for all sealed_data
    size_t total_size = 0;
    for (const auto& ks : key_shares) {
        total_size += ks.sealed_data_size;
    }

    // Allocate memory for all_key_shares
    char* all_key_shares = new char[total_size];

    size_t key_shares_size = key_shares.size();

    // Allocate memory for key_share_indexes
    uint8_t key_share_indexes[key_shares_size];

    // Fill the arrays
    size_t current_position = 0;
    for (size_t i = 0; i < key_shares_size; ++i) {

        // Copy sealed_data into all_key_shares
        memcpy(all_key_shares + current_position, key_shares[i].sealed_data, key_shares[i].sealed_data_size);
        current_position += key_shares[i].sealed_data_size;

        // Fill key_share_indexes
        key_share_indexes[i] = (uint8_t) key_shares[i].index;

    }

    size_t sealed_shares_data_size = key_shares[0].sealed_data_size;
    size_t num_key_sealed_shares = key_shares_size;

    size_t sealed_secret_size = utils::sgx_calc_sealed_data_size(0U, scheme.secret_length);
    char sealed_secret[sealed_secret_size];

    sgx_status_t ecall_ret;
    sgx_status_t  status = recover_seed(
        enclave_id, &ecall_ret,
        all_key_shares, total_size, 
        key_share_indexes, num_key_sealed_shares,
        sealed_shares_data_size, scheme.threshold,
        sealed_secret, sealed_secret_size);

    if (ecall_ret != SGX_SUCCESS) {
        std::cout << "Recove Seed Ecall failed " << std::endl;
        return;
    }  if (status != SGX_SUCCESS) {
        std::cout << "Recove Seed failed " << std::endl;
        return;
    }

    if (save_seed) {
        std::string error_message;
        bool res = db_manager::add_sealed_secret(scheme.name, sealed_secret, sealed_secret_size, error_message);

        if (!res) {
            std::cout << "Database error: " << error_message << std::endl;
            return;
        }
    }
}

void add_mnemonic(
    sgx_enclave_id_t &enclave_id,
    std::mutex &mutex_enclave_id,
    std::string& seed_name,
    size_t key_share_index,
    std::string& _mnemonics) {
    const std::lock_guard<std::mutex> lock(mutex_enclave_id);

    std::string error_message;
    db_manager::Scheme scheme;
    bool res = db_manager::get_scheme(seed_name, error_message, scheme);

    if (!res) {
        std::cout << "Database error: " << error_message << std::endl;
        return;
    }

    /* std::cout << "scheme.name: " << scheme.name << std::endl;
    std::cout << "scheme.threshold: " << scheme.threshold << std::endl;
    std::cout << "scheme.share_count: " << scheme.share_count << std::endl;
    std::cout << "scheme.secret_length: " << scheme.secret_length << std::endl;
    std::cout << "scheme.sealed_secret: " << key_to_string((const unsigned char*) scheme.sealed_secret, scheme.sealed_secret_size) << std::endl; */

    bool is_seed_empty = std::all_of(scheme.sealed_secret, scheme.sealed_secret + scheme.sealed_secret_size, [](unsigned char c) {
        return c == 0;
    });

    if (!is_seed_empty) {
        std::cout << "Seed already exists." << std::endl;
        return;
    }

    std::vector<db_manager::KeyShare> key_shares = db_manager::get_key_shares(scheme, error_message);

    // Print each key share
    /* for(const db_manager::KeyShare& ks : key_shares) {
        std::cout << "ks index: " << ks.index << " "  << key_to_string((const unsigned char*) ks.sealed_data, ks.sealed_data_size) << std::endl;
    } */

    if (key_shares.size() >= scheme.threshold) {
        std::cout << "There are already enough keys to calculate the seed." << std::endl;
        recover_seed(enclave_id, key_shares, scheme, true);
        return;
    }

    const char* mnemonics = _mnemonics.c_str();

    // --
    size_t max_secret_len = 32;
    uint8_t secret[max_secret_len];
    memset(secret, 0, max_secret_len);
    size_t secret_len = bip39_secret_from_mnemonics(mnemonics, secret, max_secret_len);
    // --

    size_t sealed_key_share_size = utils::sgx_calc_sealed_data_size(0U, max_secret_len);
    char sealed_key_share[sealed_key_share_size];

    sgx_status_t ecall_ret;
    sgx_status_t status = seal_key_share(
        enclave_id, &ecall_ret, 
        secret, max_secret_len,
        sealed_key_share, sealed_key_share_size);

    if (ecall_ret != SGX_SUCCESS) {
        std::cout << "Key share seal Ecall failed " << std::endl;
        return;
    }  if (status != SGX_SUCCESS) {
        std::cout << "Key share seal failed " << std::endl;
        return;
    }

    res = db_manager::add_sealed_key_share(seed_name, sealed_key_share, sealed_key_share_size, key_share_index, error_message);

    if (!res) {
        std::cout << "Database error: " << error_message << std::endl;
        return;
    }

    key_shares = db_manager::get_key_shares(scheme, error_message);

    if (key_shares.size() >= scheme.threshold) {
        std::cout << "There are already enough keys to calculate the seed." << std::endl;
        recover_seed(enclave_id, key_shares, scheme, true);
    } else {
        std::cout << "Key added." << std::endl;
    }
    
}

void addKeyFunction(const std::string& key) {

}

int SGX_CDECL main(int argc, char *argv[])
{
    sgx_enclave_id_t enclave_id = 0;
    std::mutex mutex_enclave_id;

    {
        const std::lock_guard<std::mutex> lock(mutex_enclave_id);

        // initialize enclave
        sgx_status_t enclave_created = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &enclave_id, NULL);
        if (enclave_created != SGX_SUCCESS) {
            printf("Enclave init error\n");
            return -1;
        }
    }

    CLI::App app{"Shamir's Secret Sharing Scheme on Intel SGX"};

    CLI::App* addKeyCmd = app.add_subcommand("add-key", "Adds a key");
    CLI::App* create_new_scheme_cmd = app.add_subcommand("create-new-scheme", "Create a new scheme. Optionally generate a new secret.");
    CLI::App* add_mnemonic_cmd = app.add_subcommand("add-mnemonic", "Generate a mnemonic");
    
    std::string newKey;
    // Options for the "add-key" subcommand
    addKeyCmd->add_option("key", newKey, "The key to add")->required();

    std::string seedName;
    size_t threshold;
    size_t shareCount;
    bool generate_seed = false;
    // Options for the "add-key" subcommand
    create_new_scheme_cmd->add_option("name", seedName, "The name of the seed")->required();
    create_new_scheme_cmd->add_option("threshold", threshold, "The threshold for this seed")->required();
    create_new_scheme_cmd->add_option("share-count", shareCount, "The total number of shares for this seed")->required();
    create_new_scheme_cmd->add_flag("-g,--generate-seed", generate_seed, "A boolean parameter");

    std::string mnemonic;
    size_t key_share_index;
    add_mnemonic_cmd->add_option("name", seedName, "The name of the seed")->required();
    add_mnemonic_cmd->add_option("key_share_index", key_share_index, "The index of this key in the Shamir secret scheme")->required();
    add_mnemonic_cmd->add_option("mnemonic", mnemonic, "The mnemonic to add")->required();

    CLI11_PARSE(app, argc, argv);

    if(*addKeyCmd) {
        addKeyFunction(newKey);
    } else if(*create_new_scheme_cmd) {
        create_new_scheme(enclave_id, mutex_enclave_id, seedName, threshold, shareCount, generate_seed);
    } else if(*add_mnemonic_cmd) {
        add_mnemonic(enclave_id, mutex_enclave_id, seedName, key_share_index, mnemonic);
    }else {
        std::cout << "No valid command was called.\n";
    }

    return 0;
}



