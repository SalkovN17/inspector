#include <crypto/certificate.hh>
#include <crypto/common.hh>
#include <crypto/digest.hh>
#include <log.hh>
#include <common.hh>

#include <openssl/pem.h>

#include <experimental/filesystem>

#include <doctest.h>

namespace crypto {
namespace fs = std::experimental::filesystem;

certificate::certificate(const std::vector<uint8_t>& data)
{
	TI_TRACE();

	const uint8_t * der_cert = data.data();
	X509 * xcert = d2i_X509(nullptr, &der_cert, data.size());
	if (!xcert)
		throw std::runtime_error("convert from der certificate failed");

	this->cert = xcert;
}

certificate::certificate(const uint8_t * data, size_t data_len)
{
	TI_TRACE();

	X509 * xcert = d2i_X509(nullptr, &data, data_len);
	if (!xcert)
		throw std::runtime_error("convert from der certificate failed");

	this->cert = xcert;
}

certificate::certificate(const std::string& path)
{
	TI_TRACE();

	FILE * file = fopen(path.c_str(), "r");
	if (!file)
	{
		std::string filename = crypto::get_filename_by_path(path);
		throw std::runtime_error("can't open file '" + filename + "' with certificate");
	}
	std::unique_ptr<FILE, decltype(&fclose)> file_ptr(file, fclose);

	X509 * xcert = PEM_read_X509_AUX(file, nullptr, nullptr, nullptr);
	if (!xcert)
	{
		std::string filename = crypto::get_filename_by_path(path);
		throw std::runtime_error("parse certificate from file '" + filename +
		                         "' failed");
	}

	this->cert = xcert;
}

certificate::certificate(csr& csr, private_key& pkey)
{
	TI_TRACE();

	X509 * xcert = X509_new();
	if (!xcert)
		throw std::runtime_error("create empty certificate failed");
	std::unique_ptr<X509, decltype(&X509_free)> xcert_ptr(xcert, X509_free);

	if (!X509_set_version(xcert, X509_VERSION_3))
		throw std::runtime_error("set version to certificate failed");

	if (!ASN1_INTEGER_set(X509_get_serialNumber(xcert), 1))
		throw std::runtime_error("set serial to certificate failed");

	if (!X509_set_subject_name(xcert, X509_REQ_get_subject_name(csr.get())))
		throw std::runtime_error("set subject name to certificate failed");

	if (!X509_set_issuer_name(xcert, X509_REQ_get_subject_name(csr.get())))
		throw std::runtime_error("set issuer name to certificate failed");

	if (!X509_set_pubkey(xcert, X509_REQ_get0_pubkey(csr.get())))
		throw std::runtime_error("set public key to certificate failed");

	if (!X509_gmtime_adj(X509_getm_notBefore(xcert), 0))
		throw std::runtime_error("set not before to certificate failed");

	if (!X509_gmtime_adj(X509_getm_notAfter(xcert), app::time_constants::seconds_per_day))
		throw std::runtime_error("set not after to certificate failed");

	if (!X509_sign(xcert, pkey.get(), digest::get(digest::algorithm::sha256)))
		throw std::runtime_error("sign certificate failed");

	this->cert = xcert_ptr.release();
}

certificate::certificate(X509 * cert) :
	cert(cert)
{
	TI_TRACE();

	if (!this->cert)
		throw std::runtime_error("certificate object can't construct from nullptr");
}

certificate::certificate(certificate&& other) noexcept :
	cert(std::exchange(other.cert, nullptr))
{
	TI_TRACE();
}

certificate& certificate::operator=(certificate&& other) noexcept
{
	TI_TRACE();

	if (this != &other)
	{
		X509_free(this->cert);
		this->cert = std::exchange(other.cert, nullptr);
	}

	return *this;
}

certificate::~certificate()
{
	TI_TRACE();
	X509_free(this->cert);
}

void certificate::save(const std::string& path) const
{
	FILE * file = fopen(path.c_str(), "w");
	if (!file)
	{
		std::string filename = crypto::get_filename_by_path(path);
		throw std::runtime_error("open file '" + filename + "' for saving certificate failed");
	}
	std::unique_ptr<FILE, decltype(&fclose)> file_ptr(file, fclose);
	fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write);

	if (PEM_write_X509(file, this->cert) != 1)
	{
		std::string filename = crypto::get_filename_by_path(path);
		throw std::runtime_error("write certificate to file '" + filename + "' failed");
	}
}

X509 * certificate::get() noexcept
{
	return this->cert;
}

std::string certificate::get_pubkey_md5() const
{
	EVP_PKEY * pubkey = X509_get0_pubkey(this->cert);

	uint8_t * der_key = nullptr;
	size_t der_key_len = i2d_PUBKEY(pubkey, &der_key);
	if (der_key_len <= 0)
		throw std::runtime_error("convert to der public key failed");

	auto der_key_free = [](uint8_t * der_key) {OPENSSL_free(der_key);};
	std::unique_ptr<uint8_t, decltype(der_key_free)> der_key_uptr(der_key, der_key_free);

	return crypto::get_data_md5(der_key, der_key_len);
}

bool certificate::operator==(const certificate& other) const
{
	return X509_cmp(this->cert, other.cert) == 0;
}

bool certificate::operator!=(const certificate& other) const
{
	return !(*this == other);
}

int certificate::get_expiration_time() const
{
	int seconds, days;
	if (1 != ASN1_TIME_diff(&days, &seconds, nullptr, X509_get_notAfter(this->cert)))
		throw std::runtime_error("diff asn1 time failed");

	if (days > 0 || seconds > 0)
		return days * app::time_constants::seconds_per_day + seconds;

	return 0;
}

int certificate::get_serial()
{
	ASN1_INTEGER * xcert_serial = X509_get_serialNumber(this->cert);
	if (!xcert_serial)
		throw std::runtime_error("no serial in certificate");
	int serial = ASN1_INTEGER_get(xcert_serial);
	return serial;
}

bool certificate::is_certificate(const std::string& path)
{
	if (!fs::exists(path))
		return false;

	FILE * file = fopen(path.c_str(), "r");
	if (!file)
	{
		std::string filename = crypto::get_filename_by_path(path);
		throw std::runtime_error("can't open file '" + filename + "' with certificate");
	}
	std::unique_ptr<FILE, decltype(&fclose)> file_ptr(file, fclose);

	X509 * xcert = PEM_read_X509_AUX(file, nullptr, nullptr, nullptr);
	std::unique_ptr<X509, decltype(&X509_free)> xcert_ptr(xcert, X509_free);

	if (!xcert)
	{
		TI_LOG(DEBUG, "file '%s' is not x509 certificates",
		       crypto::get_filename_by_path(path).c_str());
		return false;
	}

	return true;
}

std::shared_ptr<certificate> certificate::clone(certificate& orig,
                                                certificate& ca,
                                                private_key& ca_pkey,
                                                private_key& pkey)
{
	X509 * new_cert = X509_new();
	if (!new_cert)
		throw std::runtime_error("create empty certificate failed");
	std::unique_ptr<X509, decltype(&X509_free)> new_cert_ptr(new_cert, X509_free);

	X509 * orig_cert = orig.get();
	X509 * ca_cert = ca.get();
	EVP_PKEY * ca_private_key = ca_pkey.get();
	EVP_PKEY * private_key = pkey.get();

	if (!X509_set_version(new_cert, X509_get_version(orig_cert)))
		throw std::runtime_error("set version to certificate failed");

	if (!X509_set_serialNumber(new_cert, X509_get_serialNumber(orig_cert)))
		throw std::runtime_error("set serial to certificate failed");

	if (!X509_set_subject_name(new_cert, X509_get_subject_name(orig_cert)))
		throw std::runtime_error("set subject name to certificate failed");

	if (!X509_set_issuer_name(new_cert, X509_get_subject_name(ca_cert)))
		throw std::runtime_error("set issuer name to certificate failed");

	if (!X509_set_pubkey(new_cert, private_key))
		throw std::runtime_error("set public key to certificate failed");

	if (!X509_gmtime_adj(X509_getm_notBefore(new_cert), 0))
		throw std::runtime_error("set not before to certificate failed");

	if (!X509_gmtime_adj(X509_getm_notAfter(new_cert), app::time_constants::seconds_per_year))
		throw std::runtime_error("set not after to certificate failed");

	int ext_count = X509_get_ext_count(orig_cert);
	for (int i = 0; i < ext_count; i++)
	{
		X509_EXTENSION * ext = X509_get_ext(orig_cert, i);
		if (!ext)
			throw std::runtime_error("get extension from certificate failed");

		if (!X509_add_ext(new_cert, ext, -1))
			throw std::runtime_error("add extension to certificate failed");
	}

	if (!X509_sign(new_cert, ca_private_key, EVP_sha256()))
		throw std::runtime_error("sign certificate failed");

	new_cert_ptr.release();
	return std::shared_ptr<certificate>(new certificate(new_cert));
}

std::vector<uint8_t> certificate::convert_to_der() const
{
	uint8_t * data = nullptr;
	size_t data_len = i2d_X509(this->cert, &data);
	if (data_len <= 0)
		throw std::runtime_error("convert cert to der failed");

	auto data_free = [](uint8_t * data) {
		OPENSSL_free(data);
	};
	std::unique_ptr<uint8_t, decltype(data_free)> data_uptr(data, data_free);
	return std::vector<uint8_t>(data, data + data_len);
}

bool certificate::subject_is_eq(const x509_name& subject_name)
{
	return X509_NAME_cmp(X509_get_subject_name(this->cert), subject_name.get()) == 0;
}

X509 * certificate::release()
{
	X509 * xcert = this->cert;
	this->cert = nullptr;
	return xcert;
}
}; // namespace crypto
