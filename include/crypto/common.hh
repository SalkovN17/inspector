#pragma once

#include <string>
#include <vector>

namespace crypto
{
std::vector<uint8_t> generate_random_bytes(int len);
int create_asn1_object(const std::string& oid,
						const std::string& sn,
						const std::string& ln);
std::string get_data_md5(const uint8_t * data, size_t data_len);
std::string get_filename_by_path(const std::string& path);
std::string convert_to_base64url(const std::vector<uint8_t>& data);
std::vector<uint8_t> convert_from_base64url(std::string& base64_data_url);
std::string convert_to_base64(const std::vector<uint8_t>& data);
std::vector<uint8_t> convert_from_base64(const std::string& data);
}; // namespace crypto
