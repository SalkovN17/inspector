#include <crypto/pkcs7.hh>
#include <crypto/common.hh>

#include <openssl/rand.h>
#include <openssl/asn1.h>

#include <log.hh>

#include <stdexcept>

#include <doctest.h>

namespace crypto {

pkcs7::pkcs7(PKCS7 * cms) :
	cms(cms)
{
	TI_TRACE();

	if (!this->cms)
		throw std::runtime_error("pkcs7 object can't construct from nullptr");
}

pkcs7::pkcs7()
{
	TI_TRACE();

	PKCS7 * cms = PKCS7_new();
	if (!cms)
		throw std::runtime_error("create empty pkcs7 failed");

	this->cms = cms;
}

pkcs7::pkcs7(const std::vector<uint8_t>& data)
{
	TI_TRACE();

	const uint8_t * der_pkcs7 = data.data();
	PKCS7 * cms = d2i_PKCS7(nullptr, &der_pkcs7, data.size());
	if (!cms)
		throw std::runtime_error("convert from der pkcs7 failed");

	this->cms = cms;
}

pkcs7::pkcs7(const uint8_t * data, size_t data_len)
{
	TI_TRACE();

	PKCS7 * cms = d2i_PKCS7(nullptr, &data, data_len);
	if (!cms)
		throw std::runtime_error("convert from der pkcs7 failed");

	this->cms = cms;
}

pkcs7::pkcs7(pkcs7&& other) noexcept :
	cms(std::exchange(other.cms, nullptr))
{
	TI_TRACE();
}

pkcs7& pkcs7::operator=(pkcs7&& other) noexcept
{
	TI_TRACE();

	if (this != &other)
	{
		PKCS7_free(this->cms);
		this->cms = std::exchange(other.cms, nullptr);
	}

	return *this;
}

pkcs7::~pkcs7()
{
	TI_TRACE();
	PKCS7_free(this->cms);
}

PKCS7 * pkcs7::get()
{
	return this->cms;
}

void pkcs7::set_type(const pkcs7::type type)
{
	if (!PKCS7_set_type(this->get(), static_cast<int>(type)))
		throw std::runtime_error("set type for pkcs7 failed");

	this->cms->d.sign->contents->type = OBJ_nid2obj(NID_pkcs7_data);
}

void pkcs7::add_certificate(certificate& certificate)
{
	if (!PKCS7_add_certificate(this->get(), certificate.get()))
		throw std::runtime_error("add certificate to pkcs7 failed");
}

PKCS7_SIGNER_INFO * pkcs7::get_last_signer()
{
	STACK_OF(PKCS7_SIGNER_INFO) * signers = PKCS7_get_signer_info(this->get());
	if (!signers)
		throw std::runtime_error("can't get signers from pkcs7");

	int last_added_idx = sk_PKCS7_SIGNER_INFO_num(signers) - 1;
	PKCS7_SIGNER_INFO * si = sk_PKCS7_SIGNER_INFO_value(signers, last_added_idx);
	if (!si)
		throw std::runtime_error("can't get last signer from pkcs7");

	return si;
}

void pkcs7::add_signer_attribute_string(int attr_nid, const std::string& str)
{
	PKCS7_SIGNER_INFO * si = this->get_last_signer();

	ASN1_STRING * asn1_string = ASN1_STRING_new();
	if (!asn1_string)
		throw std::runtime_error("create empty asn1 string failed");

	if ((!ASN1_STRING_set(asn1_string, str.data(), str.length())))
	{
		ASN1_STRING_free(asn1_string);
		throw std::runtime_error("set data to asn1 string failed");
	}

	if (!PKCS7_add_signed_attribute(si, attr_nid, V_ASN1_PRINTABLESTRING, asn1_string))
	{
		ASN1_STRING_free(asn1_string);
		throw std::runtime_error("add attribute to pkcs7 failed");
	}
}

void pkcs7::add_signer_attribute_octet(int attr_nid, const std::vector<uint8_t>& octets)
{
	PKCS7_SIGNER_INFO * si = this->get_last_signer();

	ASN1_STRING * asn1_string = ASN1_STRING_new();
	if (!asn1_string)
		throw std::runtime_error("create empty asn1 string failed");

	if ((!ASN1_STRING_set(asn1_string, octets.data(), octets.size())))
	{
		ASN1_STRING_free(asn1_string);
		throw std::runtime_error("set data for asn1 string failed");
	}

	if (!PKCS7_add_signed_attribute(si, attr_nid, V_ASN1_OCTET_STRING, asn1_string))
	{
		ASN1_STRING_free(asn1_string);
		throw std::runtime_error("add attribute to pkcs7 failed");
	}
}

void pkcs7::add_signer(certificate& cert,private_key& key,
                       digest::algorithm digest_algorithm)
{
	PKCS7_SIGNER_INFO * si = PKCS7_add_signature(this->get(), cert.get(), key.get(),
		                                         digest::get(digest_algorithm));
	if (!si)
		throw std::runtime_error("add signer to pkcs7 failed");
}

void pkcs7::add_content(const std::vector<uint8_t>& data)
{
	PKCS7_SIGNER_INFO * si = this->get_last_signer();
	if (!PKCS7_add_signed_attribute(si, NID_pkcs9_contentType, V_ASN1_OBJECT,
	                                OBJ_nid2obj(NID_pkcs7_data)))
		throw std::runtime_error("add attribute to pkcs7 failed");

	if (!PKCS7_content_new(this->get(), NID_pkcs7_data))
		throw std::runtime_error("create content for pkcs7 failed");

	BIO * bio = PKCS7_dataInit(this->get(), nullptr);
	if (!bio)
		throw std::runtime_error("create buffer to save csr into pkcs7 failed");
	std::unique_ptr<BIO, decltype(&BIO_free_all)> bio_uptr(bio, BIO_free_all);

	if (data.size() != static_cast<size_t>(BIO_write(bio, data.data(), data.size())))
		throw std::runtime_error("write content into buffer for pkcs7 failed");

	if (!PKCS7_dataFinal(this->get(), bio))
		throw std::runtime_error("save content to pkcs7 failed");
}

void pkcs7::add_content(const csr& csr)
{
	this->add_content(csr.convert_to_der());
}

void pkcs7::add_content(const pkcs7& pkcs7)
{
	this->add_content(pkcs7.convert_to_der());
}

std::vector<uint8_t> pkcs7::convert_to_der() const
{
	uint8_t * data = nullptr;
	size_t data_len = i2d_PKCS7(this->cms, &data);
	if (data_len <= 0)
		throw std::runtime_error("convert pkcs7 to der failed");

	auto data_free = [](uint8_t * data) {
		OPENSSL_free(data);
	};
	std::unique_ptr<uint8_t, decltype(data_free)> data_uptr(data, data_free);
	return std::vector<uint8_t>(data, data + data_len);
}

std::vector<uint8_t> pkcs7::get_content()
{
	BIO * bio = PKCS7_dataInit(this->cms, nullptr);
	if (!bio)
		throw std::runtime_error("get pkcs7 content failed");
	std::unique_ptr<BIO, decltype(&BIO_free_all)> bio_uptr(bio, BIO_free_all);

	uint8_t * data = nullptr;
	size_t data_len = BIO_get_mem_data(bio, &data);
	if (data_len <= 0)
		throw std::runtime_error("invalid size of pkcs7 content");

	return std::vector<uint8_t>(data, data + data_len);
}

bool pkcs7::verify_signature(certificate& ca)
{
	BIO * bio = PKCS7_dataInit(this->cms, nullptr);
	if (!bio)
		throw std::runtime_error("get pkcs7 content failed");
	std::unique_ptr<BIO, decltype(&BIO_free_all)> bio_uptr(bio, BIO_free_all);

	char buf[1024];
	while (BIO_read(bio, buf, sizeof(buf)) > 0)
		continue;

	PKCS7_SIGNER_INFO * si = this->get_last_signer();
	return PKCS7_signatureVerify(bio, this->cms, si, ca.get()) <= 0 ? false : true;
}

std::string pkcs7::get_signer_attribute_string(int attr_nid)
{
	PKCS7_SIGNER_INFO * si = this->get_last_signer();

	ASN1_TYPE * attr = PKCS7_get_signed_attribute(si, attr_nid);
	if (!attr)
		throw std::runtime_error("get string attribute from pkcs7 failed");

	const unsigned char * data = ASN1_STRING_get0_data(attr->value.printablestring);
	return std::string(reinterpret_cast<const char *>(data));
}

std::vector<uint8_t> pkcs7::get_signer_attribute_octet(int attr_nid)
{
	PKCS7_SIGNER_INFO * si = this->get_last_signer();

	ASN1_TYPE * attr = PKCS7_get_signed_attribute(si, attr_nid);
	if (!attr)
		throw std::runtime_error("get octet attribute from pkcs7 failed");

	const uint8_t * data = ASN1_STRING_get0_data(attr->value.octet_string);
	if (!data)
		throw std::runtime_error("get data from attribute failed");
	size_t data_len = ASN1_STRING_length(attr->value.octet_string);

	return std::vector<uint8_t>(data, data + data_len);
}

std::vector<uint8_t> pkcs7::decrypt_content(private_key& recipient_key,
                                            certificate& recipient_cert)
{
	BIO * bio = BIO_new(BIO_s_mem());
	if (!bio)
		throw std::runtime_error("create buffer for pkcs7 decrypted data failed");
	std::unique_ptr<BIO, decltype(&BIO_free)> bio_uptr(bio, BIO_free);

	if (PKCS7_decrypt(this->cms, recipient_key.get(), recipient_cert.get(), bio, 0) != 1)
		throw std::runtime_error("decrypt pkcs7 failed");

	uint8_t * data = nullptr;
	size_t data_len = BIO_get_mem_data(bio, &data);
	if (data_len <= 0)
		throw std::runtime_error("invalid size of pkcs7 decrypted data");

	return std::vector<uint8_t>(data, data + data_len);
}

cipher::algorithm pkcs7::get_encryption_content_algorithm()
{
	if (!this->check_type(type::ENVELOPED))
		throw std::runtime_error("can't get encryption algorithm of not enveloped pkcs7");

	X509_ALGOR * x509_algor = this->cms->d.enveloped->enc_data->algorithm;
	if (!x509_algor)
		throw std::runtime_error("get encryption algorithm of enveloped pkcs7 failed");

	int nid = OBJ_obj2nid(x509_algor->algorithm);
	if (nid == NID_aes_128_cbc)
		return cipher::algorithm::aes_128;
	else if (nid == NID_des_ede3_cbc)
		return cipher::algorithm::des_ede3;

	throw std::runtime_error("unsupported encryption algorithm of enveloped pkcs7");
}

pkcs7 pkcs7::create_encrypted_content(const std::vector<uint8_t>& data,
                                      certificate& recipient_cert,
                                      const cipher::algorithm cipher_algorithm)
{
	STACK_OF(X509) * recipients = sk_X509_new_null();
	if (!recipients)
		throw std::runtime_error("create array for recipients certificates failed");
	auto recipients_free = [](STACK_OF(X509) * recipients) {sk_X509_free(recipients);};
	std::unique_ptr<STACK_OF(X509),
	                decltype(recipients_free)> recipients_uptr(recipients, recipients_free);
	if (!sk_X509_push(recipients, recipient_cert.get()))
		throw std::runtime_error("add certificate to recipients certificates array failed");

	BIO * bio = BIO_new(BIO_s_mem());
	if (!bio)
		throw std::runtime_error("create buffer for encrypted content failed");
	std::unique_ptr<BIO, decltype(&BIO_free)> bio_uptr(bio, BIO_free);
	if (data.size() != static_cast<size_t>(BIO_write(bio, data.data(), data.size())))
		throw std::runtime_error("write content for encryption into buffer failed");

	PKCS7 * encrypted_cms = PKCS7_encrypt(recipients, bio,
	                                      cipher::get(cipher_algorithm), PKCS7_BINARY);
	if (!encrypted_cms)
		throw std::runtime_error("encrypt content failed");

	return pkcs7(encrypted_cms);
}

pkcs7 pkcs7::create_encrypted_content(const csr& csr,
                                      certificate& recipient_cert,
                                      const cipher::algorithm cipher_algorithm)
{
	return pkcs7::create_encrypted_content(csr.convert_to_der(), recipient_cert, cipher_algorithm);
}

certificate pkcs7::get_certificate() const
{
	const STACK_OF(X509) * certs = this->cms->d.sign->cert;
	const X509 * cert = sk_X509_value(certs, 0);
	if (!cert)
		throw std::runtime_error("get certificate from pkcs7 failed");

	BIO * bio = BIO_new(BIO_s_mem());
	if (!bio)
		throw std::runtime_error("create buffer to der certificate failed");
	std::unique_ptr<BIO, decltype(&BIO_free)> bio_uptr(bio, BIO_free);

	if (!i2d_X509_bio(bio, cert))
		throw std::runtime_error("convert certificate to der failed");

	uint8_t * data = nullptr;
	size_t data_len = BIO_get_mem_data(bio, &data);
	if (data_len <= 0)
		throw std::runtime_error("invalid size of der certificate");

	return certificate(data, data_len);
}

bool pkcs7::check_type(const pkcs7::type type) const
{
	switch (static_cast<pkcs7::type>(type))
	{
		case pkcs7::type::SIGNED:
			return PKCS7_type_is_signed(this->cms);
		case pkcs7::type::ENVELOPED:
			return PKCS7_type_is_enveloped(this->cms);
		default:
			throw std::invalid_argument("unknown pkcs7 type");
	}
}

TEST_CASE("[crypto]pkcs7")
{
	pkcs7 pkcs;
	x509_name subject_name("test.com");
	private_key key;
	csr req(key, subject_name);
	certificate selfsigned_cert(req, key);

	pkcs.set_type(pkcs7::type::SIGNED);
	REQUIRE(pkcs.check_type(pkcs7::type::SIGNED) == true);

	pkcs.add_certificate(selfsigned_cert);
	auto cert_from_pkcs = pkcs.get_certificate();
	CHECK(cert_from_pkcs == selfsigned_cert);
	pkcs.convert_to_der();

	pkcs.add_signer(selfsigned_cert, key, digest::algorithm::sha256);

	std::string string_for_pkcs7 = "password";
	pkcs.add_signer_attribute_string(NID_pkcs9_challengePassword, string_for_pkcs7);
	auto string_from_pkcs7 = pkcs.get_signer_attribute_string(NID_pkcs9_challengePassword);
	CHECK(string_from_pkcs7 == string_for_pkcs7);

	std::vector<uint8_t> octet_for_pkcs7 = generate_random_bytes(10);
	pkcs.add_signer_attribute_octet(NID_pkcs9_messageDigest, octet_for_pkcs7);
	auto octet_from_pkcs7 = pkcs.get_signer_attribute_octet(NID_pkcs9_messageDigest);
	CHECK(octet_from_pkcs7 == octet_for_pkcs7);

	pkcs.add_content(req);
	auto der_csr_from_pkcs7 = pkcs.get_content();
	auto der_csr = req.convert_to_der();
	CHECK(der_csr_from_pkcs7 == der_csr);

	CHECK(pkcs.verify_signature(selfsigned_cert) == true);

	auto pkcs_with_encrypted_csr =
		pkcs7::create_encrypted_content(req, selfsigned_cert, cipher::algorithm::aes_128);
	CHECK(pkcs_with_encrypted_csr.check_type(pkcs7::type::ENVELOPED));
	auto enc_alg = pkcs_with_encrypted_csr.get_encryption_content_algorithm();
	CHECK(enc_alg == cipher::algorithm::aes_128);
	auto decrypted_csr = pkcs_with_encrypted_csr.decrypt_content(key, selfsigned_cert);
	auto der_csr1 = req.convert_to_der();
	CHECK(decrypted_csr == der_csr1);

	auto der_pkcs7 = pkcs.convert_to_der();
	pkcs7 pkcs7_from_der(der_pkcs7);
	auto der_pkcs7_from_der = pkcs7_from_der.convert_to_der();
	CHECK(der_pkcs7 == der_pkcs7_from_der);
}
}; // namespace crypto
