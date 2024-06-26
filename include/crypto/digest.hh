#pragma once

#include <openssl/types.h>

namespace crypto {
class digest
{
public:
	enum class algorithm {invalid = 1, sha512, sha256, sha1};
	static const EVP_MD * get(digest::algorithm algorithm);
};
}; // namespace crypto
