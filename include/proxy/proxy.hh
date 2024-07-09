
#pragma once

#include <memory>
#include <net/proxy.hh>

#include <crypto/certificate.hh>
#include <crypto/private_key.hh>

#include <nlohmann/json.hpp>

#include <string>

#include <map>

namespace proxy {

namespace beast = boost::beast;
namespace http = boost::beast::http;
namespace asio = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

class proxy : public std::enable_shared_from_this<proxy>
{
private:
	class session : public net::proxy::session
	{
	private:
		std::weak_ptr<proxy> proxy_ptr;
	public:
		session(tcp::socket&& socket, std::weak_ptr<proxy> proxy_ptr);
		~session();

		std::shared_ptr<crypto::private_key>
		get_pkey() override;
		std::shared_ptr<crypto::certificate>
		get_certificate(crypto::certificate& peer) override;
	};

	class listener : public net::proxy::listener
	{
	private:
		std::weak_ptr<proxy> proxy_ptr;
	public:
		listener(asio::io_context& io, std::weak_ptr<proxy> proxy_ptr);
		~listener();
		std::shared_ptr<net::proxy::session> create_session(tcp::socket& socket) override;
	};

	asio::io_service& io;
	int port;
	std::string ca_pkey_path;
	std::string ca_cert_path;

	std::shared_ptr<listener> intercepting_listener;
public:
	std::mutex certs_cache_mutex;
	std::unordered_map<std::string, std::shared_ptr<crypto::certificate>> certs_cache;
	std::shared_ptr<crypto::private_key> ca_pkey;
	std::shared_ptr<crypto::certificate> ca_cert;
	std::shared_ptr<crypto::private_key> pkey;

	static void apply(std::shared_ptr<proxy>& old_proxy,
	                  std::shared_ptr<proxy>& now_proxy);
	static proxy * create(const nlohmann::json& j, asio::io_service& io);

	proxy() = delete;
	proxy(asio::io_service& io,
	      int port,
	      std::string&& ca_cert_path,
	      std::string&& ca_pkey_path);

	bool operator==(const proxy& other) const;

	void run();
	void stop();

	virtual ~proxy();
};
}; // namespace proxy
