#include <crypto/private_key.hh>
#include <crypto/common.hh>
#include <log.hh>

#include <stdexcept>

#include <openssl/pem.h>

#include <experimental/filesystem>

#include <doctest.h>

namespace crypto {
namespace fs = std::experimental::filesystem;

private_key::private_key(int key_len)
{
	TI_TRACE();

	EVP_PKEY_CTX * ctx_ptr = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
	if (!ctx_ptr)
		throw std::runtime_error("private key context create failed");
	std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(ctx_ptr, EVP_PKEY_CTX_free);

	if (EVP_PKEY_keygen_init(ctx_ptr) != 1)
		throw std::runtime_error("private key init failed");

	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx_ptr, key_len) <= 0)
		throw std::runtime_error("private key set bits failed");

	EVP_PKEY * pkey = nullptr;
	if (EVP_PKEY_keygen(ctx_ptr, &pkey) <= 0)
		throw std::runtime_error("private key generation failed");

	this->pkey = pkey;
}

private_key::private_key(const std::string& path)
{
	TI_TRACE();

	FILE * file = fopen(path.c_str(), "r");
	if (!file)
	{
		std::string filename = crypto::get_filename_by_path(path);
		throw std::runtime_error("can't open file '" + filename + "' with private key");
	}
	std::unique_ptr<FILE, decltype(&fclose)> file_ptr(file, fclose);

	EVP_PKEY * pkey = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
	if (!pkey)
	{
		std::string filename = crypto::get_filename_by_path(path);
		throw std::runtime_error("parse private key from file '" + filename +
		                         "' failed");
	}

	this->pkey = pkey;
}

private_key::private_key(private_key&& other) noexcept :
	pkey(std::exchange(other.pkey, nullptr))
{
	TI_TRACE();
}

private_key& private_key::operator=(private_key&& other) noexcept
{
	TI_TRACE();
	if (this != &other)
	{
		EVP_PKEY_free(this->pkey);
		this->pkey = std::exchange(other.pkey, nullptr);
	}

	return *this;
}

private_key::~private_key()
{
	TI_TRACE();
	EVP_PKEY_free(this->pkey);
}

void private_key::save(const std::string& path) const
{
	FILE * file = fopen(path.c_str(), "w");
	if (!file)
	{
		std::string filename = crypto::get_filename_by_path(path);
		throw std::runtime_error("open file '" + filename + "' for saving private key failed");
	}
	std::unique_ptr<FILE, decltype(&fclose)> file_ptr(file, fclose);
	fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write);

	if (PEM_write_PrivateKey(file, this->pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1)
	{
		std::string filename = crypto::get_filename_by_path(path);
		throw std::runtime_error("write private key to file '" + filename + "' failed");
	}
}

EVP_PKEY * private_key::get() noexcept
{
	return this->pkey;
}

bool private_key::is_private_key(const std::string& path)
{
	if (!fs::exists(path))
		return false;

	FILE * file = fopen(path.c_str(), "r");
	if (!file)
	{
		std::string filename = crypto::get_filename_by_path(path);
		throw std::runtime_error("can't open file '" + filename + "' with private key");
	}
	std::unique_ptr<FILE, decltype(&fclose)> file_ptr(file, fclose);

	EVP_PKEY * key = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
	std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key_ptr(key, EVP_PKEY_free);

	if (!key)
	{
		TI_LOG(DEBUG, "file '%s' is not private key",
		       crypto::get_filename_by_path(path).c_str());
		return false;
	}

	return true;
}
}; // namespace crypto
