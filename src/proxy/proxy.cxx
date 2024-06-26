#include <proxy/proxy.hh>
#include <log.hh>

namespace proxy {

proxy::session::session(tcp::socket&& socket, std::weak_ptr<proxy> proxy_ptr) :
	net::proxy::session(std::move(socket)),
	proxy_ptr(proxy_ptr)
{
	TI_TRACE();
}

proxy::session::~session()
{
	TI_TRACE();
}

proxy::listener::listener(asio::io_context& io,
                          std::weak_ptr<proxy> proxy_ptr) :
	net::proxy::listener(io),
	proxy_ptr(proxy_ptr)
{
	TI_TRACE();
}

proxy::listener::~listener()
{
	TI_TRACE();
}

std::shared_ptr<net::proxy::session> proxy::listener::create_session(tcp::socket& socket)
{
	return std::make_shared<session>(std::move(socket), this->proxy_ptr);
}

proxy::proxy(boost::asio::io_service& io,
             int port,
             std::string&& ca_cert_path,
             std::string&& ca_pkey_path) :
	io(io),
	port(port),
	ca_cert_path(std::move(ca_cert_path)),
	ca_pkey_path(std::move(ca_pkey_path))
{
	TI_TRACE();
	TI_LOG(DEBUG, "proxy constructor\n");
}

proxy::~proxy()
{
	TI_TRACE();
}

bool proxy::operator==(const proxy& other) const
{
	return this->port == other.port                 &&
	       this->ca_cert_path == other.ca_cert_path &&
	       this->ca_pkey_path == other.ca_pkey_path;
}

proxy * proxy::create(const nlohmann::json& j, boost::asio::io_service& io)
{
	if (j.find("proxy") == j.end() ||
	    j["proxy"].empty())
	{
		TI_LOG(DEBUG, "proxy not found");
		return nullptr;
	}

	auto proxy_j = j["proxy"];
	uint32_t port = proxy_j["port"].get<uint32_t>();
	std::string ca_cert_path = proxy_j["ca_cert_path"].get<std::string>();
	std::string ca_pkey_path = proxy_j["ca_pkey_path"].get<std::string>();
	return new proxy(io, port, std::move(ca_cert_path), std::move(ca_pkey_path));
}

void proxy::apply(std::shared_ptr<proxy>& old_proxy,
                  std::shared_ptr<proxy>& now_proxy)
{
	TI_LOG(DEBUG, "apply proxy");

	if (old_proxy && now_proxy)
	{
		if (*old_proxy.get() == *now_proxy.get())
		{
			TI_LOG(DEBUG, "proxy existed");
			now_proxy.swap(old_proxy);
		}
		else
		{
			TI_LOG(DEBUG, "proxy changed, proxy will be restarted");
			old_proxy->stop();
			now_proxy->run();
		}
	}
	else if (!old_proxy && now_proxy)
	{
		TI_LOG(DEBUG, "proxy added");
		now_proxy->run();
	}
	else if (old_proxy && !now_proxy)
	{
		TI_LOG(DEBUG, "proxy removed");
		old_proxy->stop();
	}
}

void proxy::run()
{
	TI_LOG(DEBUG, "proxy run");
	this->intercepting_listener.reset(new listener(this->io, this->shared_from_this()));
	this->intercepting_listener->run(boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(),
	                                                                this->port));
}

void proxy::stop()
{
	TI_LOG(DEBUG, "proxy stop");
	this->intercepting_listener->stop();
}
} // namespace proxy
