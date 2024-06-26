#pragma once

#include <openssl/ossl_typ.h>
#include <openssl/pkcs7.h>

#include <crypto/certificate.hh>
#include <crypto/digest.hh>
#include <crypto/cipher.hh>

namespace crypto {

class pkcs7
{
private:
	PKCS7 * cms;

	pkcs7(PKCS7 * cms);
	PKCS7_SIGNER_INFO * get_last_signer();
public:
	enum class type
	{
		SIGNED = NID_pkcs7_signed,
		ENVELOPED = NID_pkcs7_enveloped,
	};

	static pkcs7 create_encrypted_content(const std::vector<uint8_t>& data,
	                                      certificate& recipient_cert,
	                                      const cipher::algorithm cipher_algorithm);
	static pkcs7 create_encrypted_content(const csr& csr,
	                                      certificate& recipient_cert,
	                                      const cipher::algorithm cipher_algorithm);

	pkcs7();
	pkcs7(const std::vector<uint8_t>& data);
	pkcs7(const uint8_t * data, size_t data_len);
	pkcs7(pkcs7&& other) noexcept;
	pkcs7(const pkcs7& other) = delete;
	~pkcs7();

	pkcs7& operator=(pkcs7&& other) noexcept;
	void operator=(const pkcs7&) = delete;

	PKCS7 * get();

	void set_type(const pkcs7::type type);
	void add_certificate(certificate& certificate);
	void add_signer(certificate& cert,private_key& key,
	                digest::algorithm digest_algorithm);
	void add_signer_attribute_string(int attr_nid, const std::string& str);
	void add_signer_attribute_octet(int attr_nid, const std::vector<uint8_t>& octets);
	void add_content(const std::vector<uint8_t>& data);
	void add_content(const csr& csr);
	void add_content(const pkcs7& pkcs7);
	bool verify_signature(certificate& ca);
	std::string get_signer_attribute_string(int attr_nid);
	std::vector<uint8_t> get_signer_attribute_octet(int attr_nid);
	std::vector<uint8_t> get_content();
	std::vector<uint8_t> decrypt_content(private_key& recipient_key,
	                                     certificate& recipient_cert);
	cipher::algorithm get_encryption_content_algorithm();

	bool check_type(const pkcs7::type type) const;
	std::vector<uint8_t> convert_to_der() const;
	certificate get_certificate() const;
};
}; // namespace crypto
