#include <crypto/common.hh>

#include <openssl/rand.h>
#include <openssl/md5.h>

#include <stdexcept>

#include <memory>

#include <sstream>
#include <iomanip>

#include <map>
#include <regex>

#include <log.hh>

#include <doctest.h>

namespace crypto
{
std::vector<uint8_t> generate_random_bytes(int len)
{
	uint8_t buffer[len];
	if (1 != RAND_bytes(buffer, len))
		throw std::runtime_error("generate random bytes failed");

	return std::vector<uint8_t>(buffer, buffer + len);
}

int create_asn1_object(const std::string& oid,
                       const std::string& sn,
                       const std::string& ln)
{
	int nid = OBJ_create(oid.c_str(), sn.c_str(), ln.c_str());
	if (nid == NID_undef)
		throw std::runtime_error("get nid of " + sn + " failed");
	return nid;
}

std::string get_data_md5(const uint8_t * data, size_t data_len)
{
	EVP_MD_CTX * mdctx = EVP_MD_CTX_new();
	if (!mdctx)
		throw std::runtime_error("create digest context failed");
	std::unique_ptr<EVP_MD_CTX,
	                decltype(&EVP_MD_CTX_free)> mdctx_ptr(mdctx, EVP_MD_CTX_free);

	if (!EVP_DigestInit_ex(mdctx, EVP_md5(), nullptr))
		throw std::runtime_error("set digest context to use md5 failed");

	if (!EVP_DigestUpdate(mdctx, data, data_len))
		throw std::runtime_error("md5 data hashing failed failed");

	uint8_t md5_result[MD5_DIGEST_LENGTH];
	if (!EVP_DigestFinal_ex(mdctx, md5_result, nullptr))
		throw std::runtime_error("get digest value from digest context failed");

	std::stringstream ss;
	ss << std::hex << std::setfill('0');
	for (const auto& byte : md5_result)
		ss << std::hex << std::setw(2) << static_cast<int>(byte);

	return ss.str();
}

std::string get_filename_by_path(const std::string& path)
{
	return path.substr(path.find_last_of("/\\") + 1);
}

static std::string url_encode(char * b64, int b64_len)
{
	std::string b64url;
	b64url.reserve(b64_len * 2);

	std::map<char, std::string> encode_map = {
		{'+', "%2B"},
		{'/', "%2F"},
		{'=', "%3D"},
		{'\n',"%0A"}
	};

	for (int i = 0; i < b64_len; i++)
	{
		char c = b64[i];
		if (encode_map.find(c) != encode_map.end())
			b64url += encode_map[c];
		else
			b64url += c;
	}

	return b64url;
}

static void replace_str(std::string& str, const std::string& from, const std::string& to)
{
	size_t start_pos = 0;
	while((start_pos = str.find(from, start_pos)) != std::string::npos)
	{
		str.replace(start_pos, from.length(), to);
		start_pos += to.length();
	}
}

static void url_decode(std::string& b64_url)
{
	replace_str(b64_url, "%2B", "+");
	replace_str(b64_url, "%2F", "/");
	replace_str(b64_url, "%3D", "=");
	replace_str(b64_url, "%0A", "\n");
}

std::vector<uint8_t> convert_from_base64url(std::string& base64_data_url)
{
	url_decode(base64_data_url);

	BIO * base64bio = BIO_new(BIO_f_base64());
	if (!base64bio)
		throw std::runtime_error("create base64 bio failed");
	std::unique_ptr<BIO, decltype(&BIO_free_all)> base64bio_uptr(base64bio, BIO_free_all);

	BIO * memorybio = BIO_new_mem_buf(base64_data_url.data(), base64_data_url.length());
	if (!memorybio)
		throw std::runtime_error("create memory bio failed");

	base64bio = BIO_push(base64bio, memorybio);

	std::vector<uint8_t> data;
	unsigned char buf[1024];
	int read_len;
	while ((read_len = BIO_read(base64bio, buf, sizeof(buf))) > 0)
		data.insert(data.end(), buf, buf + read_len);

	return data;
}

std::vector<uint8_t> convert_from_base64(const std::string& base64_data)
{
	BIO * base64bio = BIO_new(BIO_f_base64());
	if (!base64bio)
		throw std::runtime_error("create base64 bio failed");
	std::unique_ptr<BIO, decltype(&BIO_free_all)> base64bio_uptr(base64bio, BIO_free_all);

	BIO * memorybio = BIO_new_mem_buf(base64_data.data(), base64_data.length());
	if (!memorybio)
		throw std::runtime_error("create memory bio failed");

	base64bio = BIO_push(base64bio, memorybio);

	std::vector<uint8_t> data;
	unsigned char buf[1024];
	int read_len;
	while ((read_len = BIO_read(base64bio, buf, sizeof(buf))) > 0)
		data.insert(data.end(), buf, buf + read_len);

	return data;
}

std::string convert_to_base64url(const std::vector<uint8_t>& data)
{
	BIO * base64bio = BIO_new(BIO_f_base64());
	if (!base64bio)
		throw std::runtime_error("create base64 bio failed");
	std::unique_ptr<BIO, decltype(&BIO_free_all)> base64bio_uptr(base64bio, BIO_free_all);

	BIO * memorybio = BIO_new(BIO_s_mem());
	if (!memorybio)
		throw std::runtime_error("create memory bio failed");

	base64bio = BIO_push(base64bio, memorybio);

	if (static_cast<int>(data.size()) != BIO_write(base64bio, data.data(), data.size()))
		throw std::runtime_error("convert data to base64 failed");
	if (1 != BIO_flush(base64bio))
		throw std::runtime_error("flush base64 converted data failed");

	char * b64 = nullptr;
	int b64_len = BIO_get_mem_data(base64bio, &b64);
	return url_encode(b64, b64_len);
}

std::string convert_to_base64(const std::vector<uint8_t>& data)
{
	BIO * base64bio = BIO_new(BIO_f_base64());
	if (!base64bio)
		throw std::runtime_error("create base64 bio failed");
	std::unique_ptr<BIO, decltype(&BIO_free_all)> base64bio_uptr(base64bio, BIO_free_all);

	BIO * memorybio = BIO_new(BIO_s_mem());
	if (!memorybio)
		throw std::runtime_error("create memory bio failed");

	base64bio = BIO_push(base64bio, memorybio);

	if (static_cast<int>(data.size()) != BIO_write(base64bio, data.data(), data.size()))
		throw std::runtime_error("convert data to base64 failed");
	if (1 != BIO_flush(base64bio))
		throw std::runtime_error("flush base64 converted data failed");

	char * b64 = nullptr;
	BIO_get_mem_data(base64bio, &b64);
	return std::string(b64);
}

TEST_CASE("[crypto]common")
{
	SUBCASE("checking base64 encode and decode")
	{
		auto data = crypto::generate_random_bytes(100);
		auto base64_data = crypto::convert_to_base64(data);
		auto data_from_base64 = crypto::convert_from_base64(base64_data);
		CHECK(data == data_from_base64);
	}

	SUBCASE("checking base64 url encode and decode")
	{
		auto data = crypto::generate_random_bytes(100);
		auto base64_data = crypto::convert_to_base64url(data);
		auto data_from_base64 = crypto::convert_from_base64url(base64_data);
		CHECK(data == data_from_base64);
	}

	SUBCASE("checking md5 conversion")
	{
		auto data = crypto::generate_random_bytes(100);
		auto md5_l = crypto::get_data_md5(data.data(), data.size());
		auto md5_r = crypto::get_data_md5(data.data(), data.size());
		CHECK(md5_l == md5_r);
	}

	SUBCASE("checking random bytes generation")
	{
		auto random_bytes_1 = crypto::generate_random_bytes(100);
		CHECK(random_bytes_1.size() == 100);

		auto random_bytes_2 = crypto::generate_random_bytes(100);
		CHECK(random_bytes_1 != random_bytes_2);
	}
}
}; // namespace crypto
