#include <crypto/digest.hh>
#include <log.hh>

#include <openssl/evp.h>

#include <stdexcept>

#include <doctest.h>

namespace crypto {
const EVP_MD * digest::get(digest::algorithm algorithm)
{
	switch (algorithm)
	{
		case digest::algorithm::sha512:
			return EVP_sha512();
		case digest::algorithm::sha256:
			return EVP_sha256();
		case digest::algorithm::sha1:
			return EVP_sha1();
		default:
			throw std::invalid_argument("unsupported digest algorithm");
	}
}
}; // namespace crypto
