#include <net/proxy.hh>
#include <log.hh>

#include <iostream>

#include <linux/netfilter_ipv4.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

namespace net {
namespace proxy{

listener::listener(asio::io_context& io) :
	io(io),
	acceptor(asio::make_strand(io))
{
	TI_TRACE();
}

listener::~listener()
{
	TI_TRACE();
}

void listener::run(tcp::endpoint endpoint)
{
	beast::error_code ec;

	this->acceptor.open(endpoint.protocol(), ec);
	if (ec)
		throw std::runtime_error("open endpoint failed");

	this->acceptor.set_option(asio::socket_base::reuse_address(true), ec);
	if (ec)
		throw std::runtime_error("set option failed");

	this->acceptor.bind(endpoint, ec);
	if (ec)
		throw std::runtime_error("bind endpoint failed");

	this->acceptor.listen(asio::socket_base::max_listen_connections, ec);
	if (ec)
		throw std::runtime_error("listen failed");

	this->do_accept();
}

void listener::stop()
{
	this->acceptor.close();
}

void listener::do_accept()
{
	auto on_accept = beast::bind_front_handler(&listener::on_accept, this->shared_from_this());
	this->acceptor.async_accept(asio::make_strand(this->io), std::move(on_accept));
}

void listener::on_accept(beast::error_code ec, tcp::socket socket)
{
	TI_LOG(DEBUG, "on_accept");
	if (ec == asio::error::operation_aborted)
		return;

	if (ec)
	{
		TI_LOG(DEBUG, "accept connection failed");
	}
	else
	{
		auto s = this->create_session(socket);
		asio::post(this->io, [s](){
			s->run();
		});
	}

	this->do_accept();
}

session::session(asio::ip::tcp::socket&& socket) :
	server_ssl_ctx(ssl::context::tlsv12),
	client_ssl_ctx(ssl::context::tlsv12),
	server_stream(std::move(socket), server_ssl_ctx),
	client_stream(socket.get_executor(), client_ssl_ctx)
{
	TI_TRACE();

	this->client_ssl_ctx.set_verify_mode(ssl::verify_none);
}

session::~session()
{
	TI_TRACE();
}

tcp::endpoint session::get_original_dst()
{
	auto& socket = beast::get_lowest_layer(this->server_stream).socket();
	int sock_fd = socket.native_handle();

	struct sockaddr_in orig_dst;
	socklen_t orig_dst_len = sizeof(orig_dst);
	if (getsockopt(sock_fd, SOL_IP, SO_ORIGINAL_DST, &orig_dst, &orig_dst_len) == -1)
	{
		TI_LOG(DEBUG, "get original dst from socket failed");
		this->do_close();
	}

	asio::ip::address ip_address = asio::ip::address::from_string(inet_ntoa(orig_dst.sin_addr));
	unsigned short port = ntohs(orig_dst.sin_port);
	return tcp::endpoint(ip_address, port);
}

void session::run()
{
	auto original_endpoint = this->get_original_dst();
	this->connect_to_server(original_endpoint);
}

void session::connect_to_server(tcp::endpoint& endpoint)
{
	auto& client_tcp_stream = beast::get_lowest_layer(this->client_stream);
	client_tcp_stream.expires_after(std::chrono::seconds(30));

	auto on_connect = beast::bind_front_handler(&session::on_connect_to_server,
	                                            this->shared_from_this());
	client_tcp_stream.async_connect(endpoint, std::move(on_connect));
}

void session::on_connect_to_server(beast::error_code ec)
{
	if (ec)
	{
		TI_LOG(DEBUG, "connect to server failed");
		return this->do_close();
	}

	this->handshake_with_server();
}

void session::handshake_with_server()
{
	auto on_handshake_with_server = beast::bind_front_handler(&session::on_handshake_with_server,
	                                                          this->shared_from_this());

	this->client_stream.async_handshake(ssl::stream_base::client,
	                                    std::move(on_handshake_with_server));
}

void session::on_handshake_with_server(beast::error_code ec)
{
	if (ec)
	{
		TI_LOG(DEBUG, "handshake with server failed: %s", ec.message().c_str());
		return this->do_close();
	}

	TI_LOG(DEBUG, "handshake with server done!");
	this->do_close();
}

void session::do_close()
{
	beast::error_code ec;

	auto& client_tcp_stream = beast::get_lowest_layer(this->client_stream);
	auto& server_tcp_stream = beast::get_lowest_layer(this->server_stream);
	client_tcp_stream.socket().shutdown(asio::ip::tcp::socket::shutdown_send, ec);
	server_tcp_stream.socket().shutdown(asio::ip::tcp::socket::shutdown_send, ec);
}
}; // namespace proxy
}; // namespace net
