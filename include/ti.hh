#pragma once

#include <core.hh>

#include <boost/thread.hpp>

#include <mutex>

#include <tasks/task_creator.hh>

#include <nlohmann/json.hpp>

namespace app {
class ti : public tasks::task_creator
{
private:
	static void create(nlohmann::json& j);
	static void set_core(core * c);
	static void parse_config(const std::string& config);

	boost::asio::io_service io;
	boost::thread_group io_threads;
	boost::asio::signal_set signals;

	std::string config;

	std::unique_ptr<core> now_core;
	std::unique_ptr<core> old_core;

	ti();
public:
	static constexpr auto& default_config_file = "/home/compick/tls-inspector/tls-inspector.conf";
	static const int io_threads_limit = 2;

	static void init(const std::string& config);
	static void deinit();
	static void run();
	static void stop();

	static void update_core();

	static core& get_core();
	static core& get_old_core();
	static boost::asio::io_service& get_io();
	static ti& get();

	~ti();
};
}; // namespace app
