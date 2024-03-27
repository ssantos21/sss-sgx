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


// extracted from sdk/tseal/tSeal_util.cpp
/* uint32_t sgx_calc_sealed_data_size(const uint32_t add_mac_txt_size, const uint32_t txt_encrypt_size) 
{
    if(add_mac_txt_size > UINT32_MAX - txt_encrypt_size)
        return UINT32_MAX;
    uint32_t payload_size = add_mac_txt_size + txt_encrypt_size; //Calculate the payload size

    if(payload_size > UINT32_MAX - sizeof(sgx_sealed_data_t))
        return UINT32_MAX;
    return (uint32_t)(sizeof(sgx_sealed_data_t) + payload_size);
} */

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

/* application entry 
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    int untrusted_x = 123456789;

    // initialize enclave
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Enclave init error\n");
        getchar();
        return -1;
    }
 
    // invoke trusted_func01();
    int returned_result;
    ret = trusted_func01(global_eid, &returned_result);
    if (ret != SGX_SUCCESS) {
        printf("Enclave call error\n");
        return -1;
    }

    // destroy the enclave
    sgx_destroy_enclave(global_eid);

    printf ("X (untrusted): %d\n", untrusted_x);
    printf ("X (trusted): %d\n", returned_result);

    return 0;
}*/

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

    std::cout << "sealedTotalShareSize: " << sealedTotalShareSize << std::endl;

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

    // std::cout << "Secret generated successfully" << std::endl;

    // auto sealedSecretHex = key_to_string((const unsigned char*) sealedSecret, sealedSecretSize);

    // std::cout << "sealedSecret: " << sealedSecretHex << std::endl;


    res = db_manager::add_sealed_secret(seedName, sealedSecret, sealedSecretSize, error_message);

    if (!res) {
        std::cout << "Database error: " << error_message << std::endl;
        return;
    }

    // std::vector<std::vector<char>> arrays;
    for (size_t i = 0; i < shareCount; ++i) {
        // std::vector<char> share(sealedSecretSize);
        // memcpy(share.data(), sealedShares + i * sealedSecretSize, sealedSecretSize);
        // arrays.push_back(share);

        char sealed_key_share[sealedSecretSize];
        memcpy(sealed_key_share, sealedShares + i * sealedSecretSize, sealedSecretSize);
        // std::cout << "Share " << i << ": " << key_to_string((const unsigned char*) share, sealedSecretSize) << std::endl;

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
    std::cout << "OK " << std::endl;
    std::cout << "Scheme created, seed generated." << res << std::endl;
    
}

void recover_seed(sgx_enclave_id_t &enclave_id, std::vector<db_manager::KeyShare> &key_shares, db_manager::Scheme &scheme) {
    
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

        // std::cout << "key_share " << i << " " << key_to_string((const unsigned char*) key_shares[i].sealed_data, key_shares[i].sealed_data_size) << std::endl;

        // Copy sealed_data into all_key_shares
        memcpy(all_key_shares + current_position, key_shares[i].sealed_data, key_shares[i].sealed_data_size);
        current_position += key_shares[i].sealed_data_size;

        // Fill key_share_indexes
        key_share_indexes[i] = (uint8_t) key_shares[i].index;

        // std::cout << "key_share_indexes " << i << " " << key_share_indexes[i] << std::endl;
    }

    // std::cout << "all_key_shares: " << key_to_string((const unsigned char*) all_key_shares, total_size) << std::endl;

    size_t sealed_shares_data_size = key_shares[0].sealed_data_size;
    size_t num_key_sealed_shares = key_shares_size;

    size_t sealed_secret_size = utils::sgx_calc_sealed_data_size(0U, scheme.secret_length);
    char sealed_secret[sealed_secret_size];

    sgx_status_t ecall_ret;

    // print indexes
    for (size_t i = 0; i < key_shares_size; ++i) {
        std::cout << "key_share_indexes " << i << " " << key_share_indexes[i] << std::endl;
    }

    sgx_status_t status = test_indexes(
        enclave_id, &ecall_ret,
        key_share_indexes, key_shares_size);

    if (ecall_ret != SGX_SUCCESS) {
        std::cout << "test_indexes Ecall failed " << std::endl;
        return;
    }  if (status != SGX_SUCCESS) {
        std::cout << "test_indexes failed " << std::endl;
        return;
    }

    status = recover_seed(
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
        recover_seed(enclave_id, key_shares, scheme);
        return;
    }

    const char* mnemonics = _mnemonics.c_str();

    std::cout << "mnemonics: " << mnemonics << std::endl;

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

    std::cout << "secret: " << key_to_string((const unsigned char*) secret, max_secret_len) << std::endl;

    std::cout << "sealed_key_share_size: " << key_to_string((const unsigned char*) sealed_key_share, sealed_key_share_size) << std::endl;

    res = db_manager::add_sealed_key_share(seed_name, sealed_key_share, sealed_key_share_size, key_share_index, error_message);

    if (!res) {
        std::cout << "Database error: " << error_message << std::endl;
        return;
    }

    key_shares = db_manager::get_key_shares(scheme, error_message);

    if (key_shares.size() >= scheme.threshold) {
        std::cout << "There are already enough keys to calculate the seed." << std::endl;
        recover_seed(enclave_id, key_shares, scheme);
        return;
    }
    
}
// only for debug

void print_uint8_array(const uint8_t* out, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(out[i]);
        if (i < len - 1) {
            std::cout << " "; // Optional: add a space between bytes for readability
        }
    }
    std::cout << std::dec << std::endl; // Switch back to decimal format to avoid affecting further prints
}

char* data_to_hex(uint8_t* in, size_t insz)
{
    char* out = (char*) malloc(insz * 2 + 1);
    uint8_t* pin = in;
    const char * hex = "0123456789abcdef";
    char* pout = out;
    for(; pin < in + insz; pout += 2, pin++){
        pout[0] = hex[(*pin>>4) & 0xF];
        pout[1] = hex[ *pin     & 0xF];
    }
    pout[0] = 0;
    return out;
}

bool hex_digit_to_bin(const char hex, char *out) {
	if (out == NULL)
		return false;

	if (hex >= '0' && hex <= '9') {
		*out = hex - '0';
	} else if (hex >= 'A' && hex <= 'F') {
		*out = hex - 'A' + 10;
	} else if (hex >= 'a' && hex <= 'f') {
		*out = hex - 'a' + 10;
	} else {
		return false;
	}

	return true;
}

size_t hex_to_data(const char *hex, uint8_t **out) {
	if (hex == NULL || *hex == '\0') {
        *out = NULL;
		return 0;
    }
    if (out == NULL) {
        return 0;
    }

	size_t len = strlen(hex);
	if (len % 2 != 0)
		return 0;
	len /= 2;

	*out = (uint8_t*) malloc(len);
	for (size_t i = 0; i < len; i++) {
  	char b1;
  	char b2;
		if (!hex_digit_to_bin(hex[i * 2], &b1) || !hex_digit_to_bin(hex[i * 2 + 1], &b2)) {
			return 0;
		}
		(*out)[i] = static_cast<uint8_t>((b1 << 4) | b2);
	}
	return len;
}

void testHex() {
    std::string keyDataHex01 = "f7ff87e4eba0703eb97687336e020affff23d5b47ed0e65f98784d753a95a06f";
    const char* keyData01 = keyDataHex01.c_str();

    std::string keyDataHex02 = "c2abf75f780d3eff060384482bff8eeff3134cd1b7f0cc5432225cc282232023";
    const char* keyData02 = keyDataHex02.c_str();

    uint8_t* out01;
    size_t len01 = hex_to_data(keyData01, &out01);

    uint8_t* out02;
    size_t len02 = hex_to_data(keyData02, &out02);

    print_uint8_array(out01, len01);
    print_uint8_array(out02, len02);

    char* reout01 = data_to_hex(out01, len01);
    char* reout02 = data_to_hex(out02, len02);

    std::cout << "reout01: " << reout01 << std::endl;
    std::cout << "reout02: " << reout02 << std::endl;

    assert(strcmp(reout01, keyData01) == 0);
    assert(strcmp(reout02, keyData02) == 0);

    free(out01);
    free(out02);
  
    free(reout01);
    free(reout02);
}

void addKeyFunction2(const std::string& key) {

    
    std::string newKey = key;

    if (newKey.substr(0, 2) == "0x") {
        newKey = newKey.substr(2);
    }
    
    const char* keyData = newKey.c_str();


    std::cout << "Original key: " << key << std::endl;
    std::cout << "New key data: " << keyData << std::endl;

    // -- create shamir

    std::string keyDataHex01 = "f7ff87e4eba0703eb97687336e020affff23d5b47ed0e65f98784d753a95a06f";
    const char* keyData01 = keyDataHex01.c_str();

    std::string keyDataHex02 = "c2abf75f780d3eff060384482bff8eeff3134cd1b7f0cc5432225cc282232023";
    const char* keyData02 = keyDataHex02.c_str();


    // printf("len01: %d\n", len01);
    // printf("len02: %d\n", len02);

    
    uint8_t threshold = 2;

    uint8_t* shares[threshold];

    uint32_t share_len = (uint32_t) hex_to_data(keyData01, &shares[0]);
    if (share_len != 32) {
        std::cout << "Key data length mismatch. Should be 32-bytes." << std::endl;
        return;
    }

    print_uint8_array(shares[0], share_len);

    share_len = (uint32_t) hex_to_data(keyData02, &shares[1]);
    if (share_len != 32) {
        std::cout << "Key data length mismatch. Should be 32-bytes." << std::endl;
        return;
    }
    
    print_uint8_array(shares[1], share_len);

    const uint8_t recovery_share_indexes_values[] = {1, 2};
    const uint8_t* recovery_share_indexes = recovery_share_indexes_values;

    uint8_t secret_data[share_len]; // the recovered secret must be 32-bytes

    const uint8_t** sharesConst = new const uint8_t*[threshold];
    for (size_t i = 0; i < threshold; ++i) {
        sharesConst[i] = shares[i];
    }

    int32_t result = recover_secret(threshold, recovery_share_indexes, sharesConst, share_len, secret_data);

    printf("result: %d\n", result);

    // const char* secret_data_hex =  data_to_hex(secret_data, result);

    // std::cout << "Recovered secret: " << secret_data_hex << std::endl;

}

// Clearly not random. Only use for tests.
void fake_random(uint8_t *buf, size_t count, void* ctx) {
  uint8_t b = 0;
  for(int i = 0; i < count; i++) {
    buf[i] = b;
    b = b + 17;
  }
}

void addKeyFunction(const std::string& key) {

    std::cout << "Original key: " << key << std::endl;

    std::string finalKey = "4823a86fb00a38d36d1e93f6456ff61fed70b58ee3e08cf84e7980608c41ca53";
    const char* secret = finalKey.c_str();

    uint8_t share_count = 3;
    uint8_t threshold = 2;

    char* output_shares[share_count];

    uint8_t* secret_data;
    size_t secret_len = hex_to_data(secret, &secret_data);

    size_t result_len = share_count * secret_len;
    uint8_t result_data[result_len];

    int32_t result = split_secret(threshold, share_count, secret_data, secret_len, result_data, NULL, fake_random);
    printf("result: %d\n", result);
    assert(result == share_count);

    for(int i = 0; i < share_count; i++) {
        size_t offset = i * secret_len;
        output_shares[i] = data_to_hex(result_data + offset, secret_len);
        printf("output_shares[%i]: %s\n", i, output_shares[i]);
    }

    free(secret_data);
}

int SGX_CDECL main(int argc, char *argv[])
{
    // testHex();

    auto config = toml::parse_file("Settings.toml");
    auto database_connection_string = config["sss_sgx"]["database_connection_string"].as_string()->get();

    // pqxx::connection conn(database_connection_string);

    std::cout << "Database connection string: " << database_connection_string << std::endl;

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
        std::cout << "Seed name: " << seedName << std::endl;
        create_new_scheme(enclave_id, mutex_enclave_id, seedName, threshold, shareCount, generate_seed);
    } else if(*add_mnemonic_cmd) {
        add_mnemonic(enclave_id, mutex_enclave_id, seedName, key_share_index, mnemonic);
    }else {
        std::cout << "No valid command was called.\n";
    }

    /*
    add_mnemonic(
    sgx_enclave_id_t &enclave_id,
    std::mutex &mutex_enclave_id,
    std::string& seed_name,
    std::string& _mnemonics)
    */

    return 0;
}



