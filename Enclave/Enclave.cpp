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

void sss_random(uint8_t *buf, size_t count, void* ctx) {
  sgx_read_rand(buf, count);
}

char* data_to_hex(uint8_t* in, size_t insz);

sgx_status_t generate_new_secret(
    size_t threshold, 
    size_t share_count, 
    size_t secret_length,
    char *sealed_secret, size_t sealed_secret_size) {
    
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

    size_t len_p = secret_len;
    const unsigned char* priv_key_data = secret;
    ocall_print_string("--- original priv_key:");
    ocall_print_hex(&priv_key_data, (int *) &len_p);
    // ocall_print_bip39(&priv_key_data, (int *) &len_p);

    // uint8_t threshold = 2;
    // uint8_t share_count = 3;

    ocall_print_int("threshold", (const int *) &threshold);
    ocall_print_int("share_count", (const int *) &share_count);

    size_t result_len = share_count * secret_len;
    uint8_t result_data[result_len];

    int32_t result = split_secret(threshold, share_count, secret, secret_len, result_data, NULL, sss_random);
    assert(result == share_count);

    ocall_print_int("result", &result);

    for(int i = 0; i < share_count; i++) {
        size_t offset = i * secret_len;
        ocall_print_int("result_data ", &i);

        // ocall_print_hex(&r_data, (int *) &secret_len);
        char* res_i_data = data_to_hex(result_data + offset, secret_len);
        ocall_print_string(res_i_data);

        const unsigned char* r_data = result_data + offset;
        size_t len_p2 = secret_len;
        ocall_print_bip39(&r_data, (int *) &len_p2);
    }

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

// ---test

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
		(*out)[i] = (b1 << 4) | b2;
	}
	return len;
}

bool equal_strings(const char* a, const char* b) {
  return strcmp(a, b) == 0;
}

void test_hex() {
  char* hex = "000110ff";
  uint8_t* out;
  size_t len = hex_to_data(hex, &out);
  char* reout = data_to_hex(out, len);
  assert(equal_strings(hex, reout));
  free(out);
  free(reout);
}

// Clearly not random. Only use for tests.
void fake_random(uint8_t *buf, size_t count, void* ctx) {
  uint8_t b = 0;
  for(int i = 0; i < count; i++) {
    buf[i] = b;
    b = b + 17;
  }
}

static size_t _test_split_secret(const char* secret, uint8_t threshold, uint8_t share_count, char** output_shares) {
  uint8_t* secret_data;
  size_t secret_len = hex_to_data(secret, &secret_data);
  size_t result_len = share_count * secret_len;
  uint8_t result_data[result_len];
  int32_t result = split_secret(threshold, share_count, secret_data, secret_len, result_data, NULL, fake_random);
  assert(result == share_count);

  for(int i = 0; i < share_count; i++) {
    size_t offset = i * secret_len;
    output_shares[i] = data_to_hex(result_data + offset, secret_len);
  }

  free(secret_data);

  return secret_len;
}

static char* _test_recover_secret(uint8_t threshold, const char** recovery_shares, const uint8_t* recovery_share_indexes) {
  uint8_t* shares[threshold];
  size_t share_len;
  for(int i = 0; i < threshold; i++) {
    share_len = hex_to_data(recovery_shares[i], &shares[i]);
  }

  uint8_t secret_data[share_len];

  int32_t result = recover_secret(threshold, recovery_share_indexes, (const uint8_t **)shares, share_len, secret_data);
  assert(result == share_len);

  for(int i = 0; i < threshold; i++) {
    free(shares[i]);
  }

  return data_to_hex(secret_data, share_len);
}

static void _test_shamir(const char* secret, uint8_t threshold, uint8_t share_count, const uint8_t* recovery_share_indexes) {
  // printf("secret: %s\n", secret);

  char* output_shares[share_count];
  size_t secret_len = _test_split_secret(secret, threshold, share_count, output_shares);

  // for(int i = 0; i < share_count; i++) {
  //   printf("%d: %s\n", i, output_shares[i]);
  // }

  char* recovery_shares[threshold];
  for(int i = 0; i < threshold; i++) {
    recovery_shares[i] = output_shares[recovery_share_indexes[i]];
  }

  char* out_secret = _test_recover_secret(threshold, (const char **)recovery_shares, recovery_share_indexes);
  // printf("out_secret: %s\n", out_secret);

  for(int i = 0; i < share_count; i++) {
    free(output_shares[i]);
  }

  assert(equal_strings(secret, out_secret));

  free(out_secret);
}