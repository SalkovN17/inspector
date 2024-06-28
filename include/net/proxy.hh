#pragma once

#include <net/common.hh>
#include <log.hh>

#include <boost/beast.hpp>
#include <boost/beast/ssl/ssl_stream.hpp>
#include <boost/asio.hpp>

#include <crypto/certificate.hh>

namespace net {
namespace proxy{

namespace beast = boost::beast;
namespace http = boost::beast::http;
namespace asio = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

class session : public std::enable_shared_from_this<session>
{
private:
	tcp::endpoint get_original_dst();

	void connect_to_server(tcp::endpoint& endpoint);
	void on_connect_to_server(beast::error_code ec);
	void handshake_with_server();
	void on_handshake_with_server(beast::error_code ec);
	void handshake_with_client();
	void on_handshake_with_client(beast::error_code ec);
	void do_read_from_client();
	void on_read_from_client(beast::error_code ec, std::size_t bytes_transferred);
	void do_close();
protected:
	beast::flat_buffer buffer;
	std::string error;
	std::shared_ptr<http::request<http::vector_body<uint8_t>>> req;
	std::shared_ptr<http::response<http::vector_body<uint8_t>>> res;

	ssl::context server_ssl_ctx;
	ssl::context client_ssl_ctx;
	beast::ssl_stream<beast::tcp_stream> server_stream;
	beast::ssl_stream<beast::tcp_stream> client_stream;
public:
	session() = delete;
	session(tcp::socket&& socket);
	virtual ~session();

	virtual std::shared_ptr<crypto::private_key>
	get_pkey() = 0;
	virtual std::shared_ptr<crypto::certificate>
	get_certificate(crypto::certificate& peer) = 0;

	void run();
};

class listener : public std::enable_shared_from_this<listener>
{
private:
	asio::io_context& io;
	tcp::acceptor acceptor;

	void do_accept();
	void on_accept(boost::beast::error_code ec, tcp::socket socket);
public:
	listener() = delete;
	listener(asio::io_context& io);
	~listener();

	void run(tcp::endpoint endpoint);
	void stop();
	virtual std::shared_ptr<session> create_session(tcp::socket& socket) = 0;
};
}; // namespace server
}; // namespace net
