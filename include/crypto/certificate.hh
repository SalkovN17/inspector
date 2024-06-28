#pragma once

#include <openssl/ossl_typ.h>

#include <crypto/csr.hh>
#include <crypto/private_key.hh>
#include <crypto/x509_name.hh>

#include <vector>

namespace crypto {
class certificate
{
private:
	X509 * cert;
public:
	static bool is_certificate(const std::string& path);

	static std::shared_ptr<certificate> clone(certificate& orig,
	                                          certificate& ca,
	                                          private_key& ca_pkey,
	                                          private_key& pkey);

	certificate() = delete;
	certificate(const std::vector<uint8_t>& data);
	certificate(const uint8_t * data, size_t data_len);
	certificate(const std::string& path);
	certificate(csr& csr, private_key& pkey);
	certificate(X509 * cert);
	certificate(const certificate& other) = delete;
	certificate(certificate&& other) noexcept;
	~certificate();

	void operator=(const certificate&) = delete;
	certificate& operator=(certificate&& other) noexcept;
	bool operator==(const certificate& other) const;
	bool operator!=(const certificate& other) const;

	X509 * get() noexcept;

	void save(const std::string& path) const;
	std::string get_pubkey_md5() const;
	int get_expiration_time() const;
	int get_serial();
	std::vector<uint8_t> convert_to_der() const;
	bool subject_is_eq(const x509_name& subject_name);
	X509 * release();
};
}; // namespace crypto
