#pragma once

#include <openssl/x509.h>

#include <crypto/private_key.hh>

#include <vector>

#include <memory>

namespace crypto {

static const std::string empty = std::string();

class x509_name
{
private:
	X509_NAME * name;
public:
	x509_name() = delete;
	x509_name(const std::string& cn,
	          const std::string& ou = empty,
	          const std::string& o = empty,
	          const std::string& l = empty,
	          const std::string& st = empty,
	          const std::string& c = empty,
	          const std::string& mail = empty);
	x509_name(const x509_name& other) = delete;
	x509_name(x509_name&& other) noexcept;
	~x509_name();

	void operator=(const x509_name&) = delete;
	x509_name& operator=(x509_name&& other) noexcept;
	bool operator==(const x509_name& other) const;
	bool operator!=(const x509_name& other) const;

	X509_NAME * get() noexcept;
	const X509_NAME * get() const noexcept;
};
}; // namespace crypto
