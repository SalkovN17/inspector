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
		throw std::runtime_error("get original dst from socket failed");
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
		return;
	}

	this->handshake_with_server();
}

std::string session::extract_sni(const char* data, std::size_t length)
{
	const unsigned char* p = reinterpret_cast<const unsigned char*>(data);
	const unsigned char* end = p + length;

	if (p + 5 > end || p[0] != 0x16 || p[1] != 0x03) {
		throw std::runtime_error("Not a valid ClientHello message");
	}
	p += 5;

	if (p + 38 > end) {
		throw std::runtime_error("Not enough data for ClientHello header");
	}
	p += 38;

	if (p + 1 > end) {
		throw std::runtime_error("Not enough data for session ID");
	}
	size_t session_id_length = p[0];
	p += 1 + session_id_length;

	if (p + 2 > end) {
		throw std::runtime_error("Not enough data for cipher suites");
	}
	size_t cipher_suites_length = (p[0] << 8) | p[1];
	p += 2 + cipher_suites_length;

	if (p + 1 > end) {
		throw std::runtime_error("Not enough data for compression methods");
	}
	size_t compression_methods_length = p[0];
	p += 1 + compression_methods_length;

	if (p + 2 > end) {
		throw std::runtime_error("Not enough data for extensions length");
	}
	size_t extensions_length = (p[0] << 8) | p[1];
	p += 2;

	while (p + 4 <= end)
	{
		size_t extension_type = (p[0] << 8) | p[1];
		size_t extension_length = (p[2] << 8) | p[3];
		p += 4;

		if (p + extension_length > end) {
			throw std::runtime_error("Not enough data for extension");
		}

		if (extension_type == 0x00) { // SNI extension
			const unsigned char* sni_data = p;
			if (sni_data + 5 <= end && sni_data[0] == 0x00) { // Hostname type
				size_t sni_length = (sni_data[3] << 8) | sni_data[4];
				const char* sni = reinterpret_cast<const char*>(sni_data + 5);
				if (sni + sni_length <= reinterpret_cast<const char*>(end)) {
					return std::string(sni, sni_length);
				} else {
					throw std::runtime_error("SNI length exceeds buffer size");
				}
			} else {
				throw std::runtime_error("Invalid SNI data");
			}
		}

		p += extension_length;
	}

	throw std::runtime_error("No SNI found");
}

void session::handshake_with_server()
{
	int sockfd = beast::get_lowest_layer(this->server_stream).socket().native_handle();

	char buf[1024] = {0};
	ssize_t peeked_length = recv(sockfd, buf, sizeof(buf), MSG_PEEK);
	if (peeked_length <= 0)
	{
		std::cout << "error, peeked_length = " << peeked_length << std::endl;
		return;
	}

	std::string sni = this->extract_sni(buf, peeked_length);

	SSL_set_tlsext_host_name(this->client_stream.native_handle(), sni.c_str());

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
		return;
	}

	TI_LOG(DEBUG, "handshake with server done!");

	this->handshake_with_client();
}

void session::handshake_with_client()
{
	X509 * cert = SSL_get_peer_certificate(this->client_stream.native_handle());
	if (!cert)
	{
		TI_LOG(DEBUG, "get peer certificate failed");
		return;
	}

	crypto::certificate orig(cert);
	try
	{
		auto pkey = this->get_pkey();
		auto new_cert = this->get_certificate(orig);
		orig.release();

		auto ctx = this->server_stream.native_handle();
		SSL_use_PrivateKey(ctx, pkey->get());
		SSL_use_certificate(ctx, new_cert->get());

		auto on_handshake_with_server = beast::bind_front_handler(&session::on_handshake_with_client,
	                                                              this->shared_from_this());
		this->server_stream.async_handshake(ssl::stream_base::server, std::move(on_handshake_with_server));
	}
	catch(const std::exception& e)
	{
		orig.release();
		throw;
	}

	return;
}

void session::on_handshake_with_client(beast::error_code ec)
{
	if (ec)
	{
		TI_LOG(DEBUG, "handshake with client failed: %s", ec.message().c_str());
		return;
	}

	TI_LOG(DEBUG, "handshake with client done!");
	this->do_read_from_client();
}

void session::do_read_from_client()
{
	req.reset(new http::request<http::vector_body<uint8_t>>());

	beast::get_lowest_layer(this->server_stream).expires_after(std::chrono::seconds(30));
	auto on_read_from_client = beast::bind_front_handler(&session::on_read_from_client,
	                                                     this->shared_from_this());
	http::async_read(this->server_stream, this->buffer, *this->req, std::move(on_read_from_client));
}

void session::on_read_from_client(beast::error_code ec, std::size_t bytes_transferred)
{
	boost::ignore_unused(bytes_transferred);

	if(ec == http::error::end_of_stream)
		return this->do_close_both_stream();

	if(ec)
	{
		TI_LOG(DEBUG, "read from client failed: %s", ec.message().c_str());
		return;
	}

	this->do_write_to_server();
	// TI_LOG(DEBUG, "read from server done");

    // for (const auto& field : *this->req) {
    //     std::cout << field.name_string() << ": " << field.value() << "\n";
    // }
}

void session::do_write_to_server()
{
	this->res.reset(new http::response<http::vector_body<uint8_t>>());

	beast::get_lowest_layer(this->client_stream).expires_after(std::chrono::seconds(30));
	auto on_write_to_server = beast::bind_front_handler(&session::on_write_to_server,
	                                                     this->shared_from_this());
	http::async_write(this->client_stream, *this->req, std::move(on_write_to_server));
}

void session::on_write_to_server(beast::error_code ec, std::size_t bytes_transferred)
{
	boost::ignore_unused(bytes_transferred);

	if (ec)
	{
		TI_LOG(DEBUG, "write to server failed: %s", ec.message().c_str());
		return;
	}

	this->do_read_from_server();
}

void session::do_read_from_server()
{
	auto on_read_from_server = beast::bind_front_handler(&session::on_read_from_server,
	                                                     this->shared_from_this());
	http::async_read(this->client_stream, this->buffer, *this->res, std::move(on_read_from_server));
}

void session::on_read_from_server(beast::error_code ec, std::size_t bytes_transferred)
{
	boost::ignore_unused(bytes_transferred);

	if (ec)
	{
		TI_LOG(DEBUG, "read from server failed: %s", ec.message().c_str());
		return;
	}

	this->do_write_to_client();
}

void session::do_write_to_client()
{
	auto on_write_to_client = beast::bind_front_handler(&session::on_write_to_client,
	                                                    this->shared_from_this(),
	                                                    this->res->need_eof());
	http::async_write(this->server_stream, *this->res, std::move(on_write_to_client));
}

void session::on_write_to_client(bool close, beast::error_code ec, std::size_t bytes_transferred)
{
	boost::ignore_unused(bytes_transferred);

	if (ec == asio::error::operation_aborted)
	{
		TI_LOG(DEBUG, "sending operation canceled");
		return;
	}

	if (ec)
	{
		TI_LOG(DEBUG, "write to client failed: %s", ec.message().c_str());
		return;
	}

	if (close)
	{
		TI_LOG(DEBUG, "client has closed connection");
		return this->do_close_both_stream();
	}

	this->do_read_from_client();
}

void session::do_close_both_stream()
{
	this->do_close_client_stream();
	this->do_close_server_stream();
}

void session::do_close_client_stream()
{
	beast::get_lowest_layer(this->client_stream).expires_after(std::chrono::seconds(30));
	auto on_close_client_stream = beast::bind_front_handler(&session::on_close_client_stream,
	                                                        this->shared_from_this());
	this->client_stream.async_shutdown(std::move(on_close_client_stream));
}

void session::on_close_client_stream(beast::error_code ec)
{
	if (ec == asio::error::eof)
		ec = {};

	if (ec)
		TI_LOG(DEBUG, "shutdown with server failed: %s", ec.message().c_str());

	beast::get_lowest_layer(this->client_stream).socket().shutdown(tcp::socket::shutdown_both, ec);

	TI_LOG(DEBUG, "connection with server closed gracefully");
}

void session::do_close_server_stream()
{
	beast::get_lowest_layer(this->server_stream).expires_after(std::chrono::seconds(30));
	auto on_close_server_stream = beast::bind_front_handler(&session::on_close_server_stream,
	                                                        this->shared_from_this());
	this->server_stream.async_shutdown(std::move(on_close_server_stream));
}

void session::on_close_server_stream(beast::error_code ec)
{
	if (ec == asio::error::eof)
		ec = {};

	if (ec)
		TI_LOG(DEBUG, "shutdown with client failed: %s", ec.message().c_str());

	beast::get_lowest_layer(this->server_stream).socket().shutdown(tcp::socket::shutdown_both, ec);
	TI_LOG(DEBUG, "connection with client closed gracefully");
}

}; // namespace proxy
}; // namespace net
