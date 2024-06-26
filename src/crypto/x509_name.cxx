#include <crypto/x509_name.hh>

#include <log.hh>

#include <openssl/x509.h>

#include <stdexcept>

namespace crypto{

x509_name::x509_name(const std::string& cn,
                     const std::string& ou,
                     const std::string& o,
                     const std::string& l,
                     const std::string& st,
                     const std::string& c,
                     const std::string& mail)
{
	TI_TRACE();

	if (cn.empty())
		throw std::runtime_error("can't create x509 name without common name");

	X509_NAME * name = X509_NAME_new();
	if (!name)
		throw std::runtime_error("create x509 name failed");
	std::unique_ptr<X509_NAME,
	                decltype(&X509_NAME_free)> name_uptr(name, X509_NAME_free);

	auto value = reinterpret_cast<const unsigned char *>(cn.c_str());
	if (!X509_NAME_add_entry_by_txt(name, SN_commonName, MBSTRING_ASC, value, -1, -1, 0))
		throw std::runtime_error("set common name to x509 name failed");

	value = reinterpret_cast<const unsigned char *>(ou.c_str());
	if (!ou.empty() &&
	    !X509_NAME_add_entry_by_txt(name, SN_organizationalUnitName, MBSTRING_ASC, value, -1, -1, 0))
		throw std::runtime_error("set organization unit to x509 name failed");

	value = reinterpret_cast<const unsigned char *>(o.c_str());
	if (!o.empty() &&
	    !X509_NAME_add_entry_by_txt(name, SN_organizationName, MBSTRING_ASC, value, -1, -1, 0))
		throw std::runtime_error("set organization to x509 name failed");

	value = reinterpret_cast<const unsigned char *>(l.c_str());
	if (!l.empty() &&
	    !X509_NAME_add_entry_by_txt(name, SN_localityName, MBSTRING_ASC, value, -1, -1, 0))
		throw std::runtime_error("set locality to x509 name failed");

	value = reinterpret_cast<const unsigned char *>(st.c_str());
	if (!st.empty() &&
	    !X509_NAME_add_entry_by_txt(name, SN_stateOrProvinceName, MBSTRING_ASC, value, -1, -1, 0))
		throw std::runtime_error("set state to x509 name failed");

	value = reinterpret_cast<const unsigned char *>(c.c_str());
	if (!c.empty() &&
	    !X509_NAME_add_entry_by_txt(name, SN_countryName, MBSTRING_ASC, value, -1, -1, 0))
		throw std::runtime_error("set country to x509 name failed");

	value = reinterpret_cast<const unsigned char *>(mail.c_str());
	if (!mail.empty() &&
	    !X509_NAME_add_entry_by_txt(name, LN_pkcs9_emailAddress, MBSTRING_ASC, value, -1, -1, 0))
		throw std::runtime_error("set mail to x509 name failed");

	this->name = name_uptr.release();
}

x509_name::~x509_name()
{
	TI_TRACE();
	X509_NAME_free(this->name);
}

x509_name::x509_name(x509_name&& other) noexcept :
	name(std::exchange(other.name, nullptr))
{
	TI_TRACE();
}

x509_name& x509_name::operator=(x509_name&& other) noexcept
{
	TI_TRACE();

	if (this != &other)
	{
		X509_NAME_free(this->name);
		this->name = std::exchange(other.name, nullptr);
	}

	return *this;
}

bool x509_name::operator==(const x509_name& other) const
{
	return X509_NAME_cmp(this->name, other.name) == 0;
}

bool x509_name::operator!=(const x509_name& other) const
{
	return X509_NAME_cmp(this->name, other.name) != 0;
}

X509_NAME * x509_name::get() noexcept
{
	return this->name;
}

const X509_NAME * x509_name::get() const noexcept
{
	return this->name;
}

}; // namespace crypto
