#pragma once

#include <net/common.hh>
#include <log.hh>

#include <boost/beast.hpp>
#include <boost/asio.hpp>

namespace net {
namespace server{

namespace http = boost::beast::http;
using tcp = boost::asio::ip::tcp;

template<class SessionType>
class listener : public std::enable_shared_from_this<listener<SessionType>>
{
private:
	boost::asio::io_context& io;
	tcp::acceptor acceptor;

	void do_accept();
	void on_accept(boost::beast::error_code ec, tcp::socket socket);
public:
	listener() = delete;
	listener(boost::asio::io_context& io);
	~listener();

	void run(tcp::endpoint endpoint);
	void stop();

	virtual std::shared_ptr<SessionType> create_session(tcp::socket& socket) = 0;
};

class session : public std::enable_shared_from_this<session>
{
private:
	boost::beast::tcp_stream stream;
	boost::beast::flat_buffer buffer;
protected:
	http::request<http::vector_body<uint8_t>> req;
	std::shared_ptr<void> res;
public:
	session() = delete;
	session(tcp::socket&& socket);
	session(session&& other);
	virtual ~session();

	void run();
	void do_read();
	void on_read(boost::beast::error_code ec, std::size_t bytes_transferred);
	template<bool isRequest, class Body, class Fields>
	void do_write(http::message<isRequest, Body, Fields>&& msg);
	void on_write(bool close, boost::beast::error_code ec, std::size_t bytes_transferred);
	void do_close();

	virtual void handle_request() = 0;
};

template<class SessionType>
listener<SessionType>::listener(boost::asio::io_context& io) :
	io(io),
	acceptor(boost::asio::make_strand(io))
{
	TI_TRACE();
}

template<class SessionType>
listener<SessionType>::~listener()
{
	TI_TRACE();
}

template<class SessionType>
void listener<SessionType>::run(tcp::endpoint endpoint)
{
	boost::beast::error_code ec;

	this->acceptor.open(endpoint.protocol(), ec);
	if (ec)
		throw std::runtime_error("open endpoint failed");

	this->acceptor.set_option(boost::asio::socket_base::reuse_address(true), ec);
	if (ec)
		throw std::runtime_error("set option failed");

	this->acceptor.bind(endpoint, ec);
	if (ec)
		throw std::runtime_error("bind endpoint failed");

	this->acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
	if (ec)
		throw std::runtime_error("listen failed");

	this->do_accept();
}

template<class SessionType>
void listener<SessionType>::stop()
{
	this->acceptor.close();
}

template<class SessionType>
void listener<SessionType>::do_accept()
{
	auto on_accept = boost::beast::bind_front_handler(&listener::on_accept, this->shared_from_this());
	this->acceptor.async_accept(boost::asio::make_strand(this->io), std::move(on_accept));
}

template<class SessionType>
void listener<SessionType>::on_accept(boost::beast::error_code ec, tcp::socket socket)
{
	TI_LOG(DEBUG, "on_accept");
	if (ec == boost::asio::error::operation_aborted)
		return;

	if (ec)
	{
		TI_LOG(DEBUG, "accept connection failed");
	}
	else
	{
		auto s = this->create_session(socket);
		boost::asio::post(this->io, [s](){
			s->run();
		});
	}

	this->do_accept();
}

template<bool isRequest, class Body, class Fields>
void session::do_write(http::message<isRequest, Body, Fields>&& msg)
{
	auto sp = std::make_shared<http::message<isRequest, Body, Fields>>(std::move(msg));
	this->res = sp;
	auto on_write = boost::beast::bind_front_handler(&session::on_write,
	                                                 this->shared_from_this(),
	                                                 sp->need_eof());
	http::async_write(this->stream, *sp, std::move(on_write));
}
}; // namespace server
}; // namespace net
