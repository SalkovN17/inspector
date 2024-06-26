#pragma once

#include <openssl/ossl_typ.h>
#include <cstddef>
#include <string>
#include <memory>

namespace crypto {
class private_key
{
private:
	static const int default_rsa_key_len = 2048;

	EVP_PKEY * pkey;
public:
	static bool is_private_key(const std::string& path);

	private_key(int key_ken = private_key::default_rsa_key_len);
	private_key(const std::string& path);
	private_key(const private_key& other) = delete;
	private_key(private_key&& other) noexcept;
	~private_key();

	private_key& operator=(private_key&& other) noexcept;
	void operator=(const private_key&) = delete;

	EVP_PKEY * get() noexcept;

	void save(const std::string& path) const;
};
}; // namespace crypto
