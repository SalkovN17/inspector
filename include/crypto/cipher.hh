#pragma once

#include <openssl/types.h>

namespace crypto {

class cipher
{
public:
	enum class algorithm {invalid = 1, aes_128, des_ede3};
	static const EVP_CIPHER * get(cipher::algorithm algorithm);
};
}; // namespace crypto
