#include <common.hh>

#include <regex>
#include <boost/date_time.hpp>

#include <doctest.h>

#define DATE_STR_BUF 32

namespace app {
std::pair<std::string, std::string> get_host_and_port_from_url(const std::string &url)
{
	std::regex url_regex("((http|https)://)?([^:/]+)(:([0-9]+))?(.*)");
	std::smatch match;

	if (std::regex_match(url, match, url_regex))
	{
		const int PROTOCOL_GROUP = 2;
		const int HOST_GROUP     = 3;
		const int PORT_GROUP     = 5;

		std::string host = match[HOST_GROUP];
		std::string port = match[PORT_GROUP];

		if (port.empty() && match[PROTOCOL_GROUP] == "http")
			port = "80";
		else if (port.empty() && match[PROTOCOL_GROUP] == "https")
			port = "443";

		return std::make_pair(host, port);
	}

	return std::make_pair("", "");
}

std::string get_date_after(int seconds)
{
	boost::posix_time::ptime date = boost::posix_time::second_clock::local_time() +
	                                boost::posix_time::seconds(seconds);
	char date_buf[DATE_STR_BUF];
	std::tm expiration_tm = boost::posix_time::to_tm(date);
	strftime(date_buf, sizeof(date_buf), "%F %H:%M:%S", &expiration_tm); // TODO: заменить на lh_strtime
	return date_buf;
}

TEST_CASE("[app]common")
{
	SUBCASE("checking parsing host and port from url")
	{
		std::string url1 = "http://127.0.0.1:8080";
		auto res1 = get_host_and_port_from_url(url1);
		CHECK(res1.first  == "127.0.0.1");
		CHECK(res1.second == "8080");

		std::string url2 = "http://example.com:8080";
		auto res2 = get_host_and_port_from_url(url2);
		CHECK(res2.first  == "example.com");
		CHECK(res2.second == "8080");

		std::string url3 = "http://127.0.0.1";
		auto res3 = get_host_and_port_from_url(url3);
		CHECK(res3.first  == "127.0.0.1");
		CHECK(res3.second == "80");

		std::string url4 = "https://127.0.0.1";
		auto res4 = get_host_and_port_from_url(url4);
		CHECK(res4.first  == "127.0.0.1");
		CHECK(res4.second == "443");

		std::string url5 = "127.0.0.1:8080";
		auto res5 = get_host_and_port_from_url(url5);
		CHECK(res5.first  == "127.0.0.1");
		CHECK(res5.second == "8080");

		std::string url6 = "example.com:8080";
		auto res6 = get_host_and_port_from_url(url6);
		CHECK(res6.first  == "example.com");
		CHECK(res6.second == "8080");

		std::string url7 = "example.com";
		auto res7 = get_host_and_port_from_url(url7);
		CHECK(res7.first  == "example.com");
		CHECK(res7.second == "");

		std::string url8 = "127.0.0.1";
		auto res8 = get_host_and_port_from_url(url8);
		CHECK(res8.first  == "127.0.0.1");
		CHECK(res8.second == "");
	}
}
}; // namespace app
