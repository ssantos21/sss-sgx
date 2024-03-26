#pragma once

#ifndef UTILS_H
#define UTILS_H

#include <string>

namespace utils {

    uint32_t sgx_calc_sealed_data_size(const uint32_t add_mac_txt_size, const uint32_t txt_encrypt_size);
    
} // namespace db_manager

#endif // UTILS_H