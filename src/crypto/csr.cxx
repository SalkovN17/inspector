#include <crypto/csr.hh>
#include <crypto/common.hh>
#include <log.hh>

#include <openssl/pem.h>

#include <stdexcept>

#include <experimental/filesystem>

#include <doctest.h>

namespace crypto {
namespace fs = std::experimental::filesystem;

csr::csr(private_key& pkey, x509_name& subject)
{
	TI_TRACE();

	X509_REQ * req = X509_REQ_new();
	if (!req)
		throw std::runtime_error("create empty csr failed");
	std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> req_uptr(req, X509_REQ_free);

	if (!X509_REQ_set_version(req, X509_REQ_VERSION_1))
		throw std::runtime_error("set version to csr failed");

	if (!X509_REQ_set_subject_name(req, subject.get()))
		throw std::runtime_error("set subject name to csr failed");

	if (!X509_REQ_set_pubkey(req, pkey.get()))
		throw std::runtime_error("set public key to csr failed");

	if (!X509_REQ_sign(req, pkey.get(), EVP_sha256()))
		throw std::runtime_error("sign csr failed");

	this->req = req_uptr.release();
}

csr::csr(const std::string& path)
{
	TI_TRACE();

	FILE * file = fopen(path.c_str(), "r");
	if (!file)
	{
		std::string filename = crypto::get_filename_by_path(path);
		throw std::runtime_error("can't open file '" + filename + "' with csr");
	}
	std::unique_ptr<FILE, decltype(&fclose)> file_ptr(file, fclose);

	X509_REQ * req = PEM_read_X509_REQ(file, nullptr, nullptr, nullptr);
	if (!req)
	{
		std::string filename = crypto::get_filename_by_path(path);
		throw std::runtime_error("parse csr from file '" + filename +
		                         "' failed");
	}

	this->req = req;
}

csr::csr(const std::vector<uint8_t>& data)
{
	TI_TRACE();

	const uint8_t * der_req = data.data();
	X509_REQ * req = d2i_X509_REQ(nullptr, &der_req, data.size());
	if (!req)
		throw std::runtime_error("convert from der csr failed");

	this->req = req;
}

csr::csr(csr&& other) noexcept :
	req(std::exchange(other.req, nullptr))
{
	TI_TRACE();
}

csr& csr::operator=(csr&& other) noexcept
{
	TI_TRACE();

	if (this != &other)
	{
		X509_REQ_free(this->req);
		this->req = std::exchange(other.req, nullptr);
	}

	return *this;
}

csr::~csr()
{
	TI_TRACE();
	X509_REQ_free(this->req);
}

void csr::save(const std::string& path) const
{
	FILE * file = fopen(path.c_str(), "w");
	if (!file)
	{
		std::string filename = crypto::get_filename_by_path(path);
		throw std::runtime_error("open file '" + filename + "' for saving csr failed");
	}
	std::unique_ptr<FILE, decltype(&fclose)> file_ptr(file, fclose);
	fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write);

	if (PEM_write_X509_REQ(file, this->req) != 1)
	{
		std::string filename = crypto::get_filename_by_path(path);
		throw std::runtime_error("write csr to file '" + filename + "' failed");
	}
}

X509_REQ * csr::get() noexcept
{
	return this->req;
}

bool csr::is_csr(const std::string& path)
{
	if (!fs::exists(path))
		return false;

	FILE * file = fopen(path.c_str(), "r");
	if (!file)
	{
		std::string filename = crypto::get_filename_by_path(path);
		throw std::runtime_error("can't open file '" + filename + "' with csr");
	}
	std::unique_ptr<FILE, decltype(&fclose)> file_ptr(file, fclose);

	X509_REQ * req = PEM_read_X509_REQ(file, nullptr, nullptr, nullptr);
	std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> req_ptr(req, X509_REQ_free);

	if (!req)
	{
		TI_LOG(DEBUG, "file '%s' is not csr",
		       crypto::get_filename_by_path(path).c_str());
		return false;
	}

	return true;
}

std::vector<uint8_t> csr::convert_to_der() const
{
	uint8_t * data = nullptr;
	size_t data_len = i2d_X509_REQ(this->req, &data);
	if (data_len <= 0)
		throw std::runtime_error("convert csr to der failed");

	auto data_free = [](uint8_t * data) {
		OPENSSL_free(data);
	};
	std::unique_ptr<uint8_t, decltype(data_free)> data_uptr(data, data_free);
	return std::vector<uint8_t>(data, data + data_len);
}
}; // namespace crypto
