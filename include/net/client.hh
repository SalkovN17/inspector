#pragma once

#include <net/common.hh>
#include <log.hh>

#include <boost/beast.hpp>
#include <boost/asio.hpp>

namespace net {
namespace client{

namespace http = boost::beast::http;
using tcp = boost::asio::ip::tcp;

template<class CloseHandler>
class session : public std::enable_shared_from_this<session<CloseHandler>>
{
protected:
	boost::beast::tcp_stream stream;
	boost::beast::flat_buffer buffer;
	std::string host;
	std::string port;

	std::string error;

	tcp::resolver resolver;
	std::shared_ptr<void> req;
	std::shared_ptr<http::response<http::vector_body<uint8_t>>> res;

	CloseHandler close_handler;
public:
	session() = delete;
	session(boost::asio::io_service& io, CloseHandler&& close_handler);
	virtual ~session();

	void run(std::string&& host, std::string&& post);
	void on_resolve(boost::beast::error_code ec, tcp::resolver::results_type results);
	void on_connect(boost::beast::error_code ec, tcp::resolver::results_type::endpoint_type);
	template<bool isRequest, class Body, class Fields>
	void do_write(http::message<isRequest, Body, Fields>&& msg);
	void on_write(boost::beast::error_code ec, std::size_t bytes_transferred);
	void on_read(boost::beast::error_code ec, std::size_t bytes_transferred);
	void do_close();

	const std::string& get_error() const &;

	virtual void handler() = 0;
};

template<class CloseHandler>
session<CloseHandler>::session(boost::asio::io_service& io, CloseHandler&& close_handler) :
	stream(boost::asio::make_strand(io)),
	resolver(boost::asio::make_strand(io)),
	close_handler(std::move(close_handler))
{
	TI_TRACE();
}

template<class CloseHandler>
session<CloseHandler>::~session()
{
	TI_TRACE();
}

template<class CloseHandler>
void session<CloseHandler>::run(std::string&& host, std::string&& post)
{
	this->host = std::move(host);
	this->port = std::move(post);
	auto on_resolve = boost::beast::bind_front_handler(&session::on_resolve,
	                                                   this->shared_from_this());
	this->resolver.async_resolve(this->host, this->port, std::move(on_resolve));
}

template<class CloseHandler>
void session<CloseHandler>::on_resolve(boost::beast::error_code ec,
                                       tcp::resolver::results_type results)
{
	if (ec)
	{
		this->error = "resolve host failed";
		return this->close_handler();
	}

	this->stream.expires_after(std::chrono::seconds(30));
	auto on_connect = boost::beast::bind_front_handler(&session::on_connect,
	                                                   this->shared_from_this());
	this->stream.async_connect(results, std::move(on_connect));
}

template<class CloseHandler>
void session<CloseHandler>::on_connect(boost::beast::error_code ec,
                                       tcp::resolver::results_type::endpoint_type)
{
	if (ec)
	{
		this->error = "connect to server failed";
		return this->close_handler();
	}

	try
	{
		this->handler();
	}
	catch(const std::exception& e)
	{
		this->error = e.what();
		this->do_close();
	}
}

template<class CloseHandler>
template<bool isRequest, class Body, class Fields>
void session<CloseHandler>::do_write(http::message<isRequest, Body, Fields>&& msg)
{
	auto sp = std::make_shared<http::message<isRequest, Body, Fields>>(std::move(msg));
	this->req = sp;
	this->res.reset(new http::response<http::vector_body<uint8_t>>());
	auto on_write = boost::beast::bind_front_handler(&session::on_write,
	                                                 this->shared_from_this());
	http::async_write(this->stream, *sp, std::move(on_write));
}

template<class CloseHandler>
void session<CloseHandler>::on_write(boost::beast::error_code ec, std::size_t bytes_transferred)
{
	boost::ignore_unused(bytes_transferred);

	if (ec)
	{
		this->error = "write to server failed";
		return this->do_close();
	}

	auto on_read = boost::beast::bind_front_handler(&session::on_read,
	                                                this->shared_from_this());
	http::async_read(this->stream, this->buffer, *this->res, std::move(on_read));
}

template<class CloseHandler>
void session<CloseHandler>::on_read(boost::beast::error_code ec, std::size_t bytes_transferred)
{
	boost::ignore_unused(bytes_transferred);

	if (ec)
	{
		this->error = "read from server failed)";
		return this->do_close();
	}

	this->req = nullptr;

	try
	{
		this->handler();
	}
	catch(const std::exception& e)
	{
		this->error = e.what();
		this->do_close();
	}
}

template<class CloseHandler>
void session<CloseHandler>::do_close()
{
	boost::beast::error_code ec;
	this->stream.socket().shutdown(tcp::socket::shutdown_both, ec);
	this->close_handler();
}

template<class CloseHandler>
const std::string& session<CloseHandler>::get_error() const &
{
	return this->error;
}
}; // namespace client
}; // namespace net
