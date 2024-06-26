#include <crypto/cipher.hh>
#include <log.hh>

#include <openssl/evp.h>

#include <stdexcept>

#include <doctest.h>

namespace crypto {
const EVP_CIPHER * cipher::get(cipher::algorithm algorithm)
{
	switch (algorithm)
	{
		case cipher::algorithm::aes_128:
			return EVP_aes_128_cbc();
		case cipher::algorithm::des_ede3:
			return EVP_des_ede3_cbc();
		default:
			throw std::invalid_argument("unsupported cipher algorithm");
	}
}
}; // namespace crypto
