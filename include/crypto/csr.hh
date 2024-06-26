#pragma once

#include <openssl/x509.h>

#include <crypto/private_key.hh>
#include <crypto/x509_name.hh>

#include <vector>

namespace crypto {
class csr
{
private:
	X509_REQ * req;
public:
	static bool is_csr(const std::string& path);

	csr() = delete;
	csr(private_key& pkey, x509_name& subject);
	csr(const std::string& path);
	csr(const std::vector<uint8_t>& data);
	csr(const csr& other) = delete;
	csr(csr&& other) noexcept;
	~csr();

	void operator=(const csr&) = delete;
	csr& operator=(csr&& other) noexcept;

	X509_REQ * get() noexcept;

	void save(const std::string& path) const;
	std::vector<uint8_t> convert_to_der() const;
};
}; // namespace crypto
