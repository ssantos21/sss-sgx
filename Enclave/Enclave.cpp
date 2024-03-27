#include "Enclave_t.h"
#include <stdio.h>
#include <string.h>

#include <bc-shamir/bc-shamir.h>

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#include <assert.h>

#include "sgx_trts.h"
#include "sgx_tseal.h"

int trusted_func01()
{
    int trusted_x = 987654321;
    ocall_wait_keyinput("Please enter keyboard to show variables in memory ...");
    return trusted_x;
}

void sss_random(uint8_t *buf, size_t count, [[maybe_unused]] void* ctx) {
  sgx_read_rand(buf, count);
}

char* data_to_hex(uint8_t* in, size_t insz);

sgx_status_t generate_new_secret(
    size_t threshold, 
    size_t share_count, 
    size_t secret_length,
    char *sealed_secret, size_t sealed_secret_size,
    char* sealed_shares, size_t sealed_total_share_size) {
    
    // Step 1: Open Context.
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_ecc_state_handle_t p_ecc_handle = NULL;

    if (share_count < threshold) {
        ocall_print_string("Error: share_count < threshold");
        return SGX_ERROR_UNEXPECTED;
    }

    if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS)
    {
        ocall_print_string("\nTrustedApp: sgx_ecc256_open_context() failed !\n");
        if (p_ecc_handle != NULL)
        {
            sgx_ecc256_close_context(p_ecc_handle);
        }
        return ret;
    }

    uint8_t secret_len = (uint8_t) secret_length;

    unsigned char secret[secret_len];
    memset(secret, 0, secret_len);

    sgx_read_rand(secret, secret_len);

    ocall_print_string("");
    char* seed = data_to_hex(secret, secret_len);
    ocall_print_string("Seed:");
    ocall_print_string(seed);
    ocall_print_string("");

    size_t result_len = share_count * secret_len;
    uint8_t result_data[result_len];

    int32_t result = split_secret((uint8_t) threshold, (uint8_t) share_count, secret, secret_len, result_data, NULL, sss_random);
    assert(result == (int32_t) share_count);

    for(size_t i = 0; i < share_count; i++) {
        size_t offset = i * secret_len;
        ocall_print_int("Key share ", (int *)  &i);

        // ocall_print_hex(&r_data, (int *) &secret_len);
        char* key_share_hex = data_to_hex(result_data + offset, secret_len);
        ocall_print_string(key_share_hex);

        const unsigned char* share_data = result_data + offset;
        size_t share_len = secret_len;
        ocall_print_bip39(&share_data, (int *) &share_len);
        ocall_print_string("");

        const size_t sealed_share_size = sealed_secret_size;

        char sealed_share[sealed_share_size];
        memset(sealed_share, 0, sealed_share_size);

        if (sealed_share_size >= sgx_calc_sealed_data_size(0U, (uint32_t) share_len))
        {
            if ((ret = sgx_seal_data(0U, NULL, (uint32_t) share_len, share_data, (uint32_t) sealed_share_size, (sgx_sealed_data_t *)sealed_share)) != SGX_SUCCESS)
            {
                ocall_print_string("\nTrustedApp: sgx_seal_data() failed !\n");
            }
        }
        else
        {
            ocall_print_string("\nTrustedApp: Size allocated for sealedprivkey by untrusted app is less than the required size !\n");
            ret = SGX_ERROR_INVALID_PARAMETER;
        }

        /* char* sealed_share_i_data = data_to_hex((uint8_t*) sealed_share, sealed_share_size);
        ocall_print_string("Saled Share i data");
        ocall_print_string(sealed_share_i_data); */

        size_t share_offset = i * sealed_share_size;

        // Ensure we don't write past the end of sealed_shares
        if ((share_offset + sealed_share_size) > sealed_total_share_size) {
            // Handle error: share would exceed total share size
            ocall_print_string("\n(share_offset + sealed_share_size) would exceed sealed_total_share_size !\n");
            return SGX_ERROR_UNEXPECTED; // Example error code, adjust according to your error handling
        }

        // add sealed_share to sealed_shares at share_offset
        memcpy(sealed_shares + share_offset, sealed_share, sealed_share_size);

    }

    /* char* sealed_shares_data = data_to_hex((uint8_t*) sealed_shares, sealed_total_share_size);
    ocall_print_string("sealed_shares_data");
    ocall_print_string(sealed_shares_data); */

    // Mnemonics
    // size_t max_mnemonics_len = 300;
    // char mnemonics[max_mnemonics_len];
    // size_t mnemonics_len = bip39_mnemonics_from_secret(secret, secret_len, mnemonics, max_mnemonics_len);
    // ocall_print_int("mnemonics_len", (const int *) &mnemonics_len);

    


    // Step 3: Calculate sealed data size.
    if (sealed_secret_size >= sgx_calc_sealed_data_size(0U, sizeof(secret)))
    {
        if ((ret = sgx_seal_data(0U, NULL, sizeof(secret), secret, (uint32_t) sealed_secret_size, (sgx_sealed_data_t *)sealed_secret)) != SGX_SUCCESS)
        {
            ocall_print_string("\nTrustedApp: sgx_seal_data() failed !\n");
        }
    }
    else
    {
        ocall_print_string("\nTrustedApp: Size allocated for sealedprivkey by untrusted app is less than the required size !\n");
        ret = SGX_ERROR_INVALID_PARAMETER;
    }

    // Step 4: Close Context.
    if (p_ecc_handle != NULL)
    {
        sgx_ecc256_close_context(p_ecc_handle);
    }


    return SGX_SUCCESS;
}

sgx_status_t seal_key_share(
  unsigned char* key_share, size_t key_share_size,
  char* sealed_key_share, size_t sealed_key_share_size) {

  sgx_status_t ret = SGX_SUCCESS;

  if (sealed_key_share_size >= sgx_calc_sealed_data_size(0U, (uint32_t) key_share_size))
  {
    if ((ret = sgx_seal_data(0U, NULL, (uint32_t) key_share_size, key_share, (uint32_t) sealed_key_share_size, (sgx_sealed_data_t *)sealed_key_share)) != SGX_SUCCESS)
    {
      ocall_print_string("\nTrustedApp: sgx_seal_data() failed !\n");
      ret =  SGX_ERROR_UNEXPECTED;
    }
  }
  else
  {
    ocall_print_string("\nTrustedApp: Size allocated for sealed_key_share_size by untrusted app is less than the required size !\n");
    ret =  SGX_ERROR_INVALID_PARAMETER;
  }

  return ret;
}

sgx_status_t recover_seed(
  char* sealed_shares, size_t sealed_total_share_size,
  unsigned char* indexes, size_t num_key_sealed_shares,
  size_t sealed_share_data_size, size_t threshold,
  char* sealed_secret, size_t sealed_secret_size) {

    (void) sealed_total_share_size;

  sgx_status_t ret = SGX_SUCCESS;

  uint8_t* shares[threshold];

  uint32_t unsealed_data_size = 0;

  for (size_t i = 0; i < num_key_sealed_shares; ++i) {
    char sealed_key_share[sealed_share_data_size];

    memcpy(sealed_key_share, sealed_shares + i * sealed_share_data_size, sealed_share_data_size);

    unsealed_data_size = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_key_share);
    uint8_t key_share[unsealed_data_size];

    if ((ret = sgx_unseal_data((sgx_sealed_data_t *)sealed_key_share, NULL, NULL, key_share, &unsealed_data_size)) != SGX_SUCCESS)
    {
        ocall_print_string("\nTrustedApp: sgx_unseal_data() failed !\n");
        return SGX_ERROR_UNEXPECTED;
    }

    shares[i] = new uint8_t[unsealed_data_size];
    memcpy(shares[i], key_share, unsealed_data_size);

  }
 
  assert(threshold == num_key_sealed_shares);

  uint8_t secret_data[unsealed_data_size];

  // for (size_t i = 0; i < threshold; ++i) {
  //   ocall_print_int("share ", (const int *) &i);
  //   ocall_print_hex((const unsigned char**) &shares[i], (int *) &unsealed_data_size);
  // }

  int32_t secret_data_len = recover_secret((uint8_t) threshold, (const uint8_t*) indexes, (const uint8_t **)shares, unsealed_data_size, secret_data);
  assert(secret_data_len == (int32_t) unsealed_data_size);

  char* seed = data_to_hex(secret_data, unsealed_data_size);
  ocall_print_string("Seed:");
  ocall_print_string(seed);

  if (sealed_secret_size >= sgx_calc_sealed_data_size(0U, unsealed_data_size))
  {
      if ((ret = sgx_seal_data(0U, NULL, unsealed_data_size, secret_data, (uint32_t) sealed_secret_size, (sgx_sealed_data_t *)sealed_secret)) != SGX_SUCCESS)
      {
          ocall_print_string("\nTrustedApp: sgx_seal_data() failed !\n");
          ret = SGX_ERROR_UNEXPECTED;
      }
  }
  else
  {
      ocall_print_string("\nTrustedApp: Size allocated for sealedprivkey by untrusted app is less than the required size !\n");
      ret = SGX_ERROR_INVALID_PARAMETER;
  }

  return ret;

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
