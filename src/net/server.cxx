#include <net/server.hh>
#include <log.hh>

namespace net {
namespace server{
session::session(boost::asio::ip::tcp::socket&& socket) :
	stream(std::move(socket))
{
	TI_TRACE();
}

session::session(session&& other) :
	stream(std::move(other.stream)),
	buffer(std::move(other.buffer)),
	req(std::move(other.req)),
	res(std::move(other.res))
{
	TI_TRACE();
}

session::~session()
{
	TI_TRACE();
}

void session::run()
{
	auto do_read = boost::beast::bind_front_handler(&session::do_read,
	                                                this->shared_from_this());
	boost::asio::dispatch(this->stream.get_executor(), std::move(do_read));
}

void session::do_read()
{
	this->req = {};
	this->stream.expires_after(std::chrono::seconds(30));
	auto on_read = boost::beast::bind_front_handler(&session::on_read,
	                                                this->shared_from_this());
	http::async_read(this->stream, this->buffer, this->req, std::move(on_read));
}

void session::on_read(boost::beast::error_code ec, std::size_t bytes_transferred)
{
	boost::ignore_unused(bytes_transferred);

	if (ec == boost::asio::error::operation_aborted)
		return;

	if (ec == http::error::end_of_stream)
		return this->do_close();

	if (ec)
	{
		TI_LOG(DEBUG, "read request failed");
		return this->do_close();
	}

	this->handle_request();
}

void session::on_write(bool close, boost::beast::error_code ec, std::size_t bytes_transferred)
{
	boost::ignore_unused(bytes_transferred);

	if (ec == boost::asio::error::operation_aborted)
		return;

	if (ec)
	{
		TI_LOG(DEBUG, "write response failed");
		return this->do_close();
	}

	if (close)
		return this->do_close();

	this->res = nullptr;
	this->do_read();
}

void session::do_close()
{
	boost::beast::error_code ec;
	this->stream.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
}
}; // namespace server
}; // namespace net
