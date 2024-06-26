#include <ti.hh>
#include <log.hh>
#include <handlers.hh>

#include <fstream>

#include <doctest.h>

namespace app {
const int ti::io_threads_limit;

ti::ti() :
	task_creator("ti", this->io),
	signals(this->io, SIGINT, SIGTERM, SIGHUP)
{
	TI_TRACE();

	this->signals.async_wait([&](const boost::system::error_code&, int sig) {
		handlers::signals(this->signals, sig);
	});
}

ti::~ti()
{
	TI_TRACE();
}

void ti::set_core(core * c)
{
	ti::get().old_core.swap(ti::get().now_core);
	ti::get().now_core.reset(c);
}

core& ti::get_core()
{
	auto core_ptr = ti::get().now_core.get();
	if (!core_ptr)
		throw std::runtime_error("can't get now core, now core doesn't exist");
	return *core_ptr;
}

core& ti::get_old_core()
{
	auto core_ptr = ti::get().old_core.get();
	if (!core_ptr)
		throw std::runtime_error("can't get old core, old core doesn't exist");
	return *core_ptr;
}

boost::asio::io_service& ti::get_io()
{
	return ti::get().io;
}

void ti::create(nlohmann::json& j)
{
	ti::set_core(new core());
	ti::get_core().proxy.reset(proxy::proxy::create(j, ti::get_io()));
}

void ti::parse_config(const std::string& config)
{
	std::ifstream i(config);
	nlohmann::json j;
	i >> j;
	ti::create(j);
}

void ti::init(const std::string& config)
{
	TI_TRACE();
	TI_LOG(DEBUG, "initialization started");
	ti::get().config = config;
	ti::get().parse_config(config);
	TI_LOG(DEBUG, "initialization completed");
}

void ti::deinit()
{
	TI_TRACE();
	TI_LOG(DEBUG, "finalize started");
	ti::update_core();
	TI_LOG(DEBUG, "finalize completed");
}

void ti::run()
{
	TI_LOG(DEBUG, "run");

	for (size_t i = 0; i < ti::io_threads_limit; i++)
		ti::get().io_threads.create_thread(boost::bind(&boost::asio::io_service::run, &ti::get_io()));
	core::run(ti::get_core());
	ti::get_io().run();
}

void ti::stop()
{
	TI_TRACE();
	TI_LOG(DEBUG, "stop");
	ti::get_io().stop();
}

ti& ti::get()
{
	static std::shared_ptr<ti> cert_mgr(new ti());
	return *cert_mgr;
}

void ti::update_core()
{
	TI_TRACE();
	TI_LOG(DEBUG, "core update started");
	ti::parse_config(ti::get().config);
	core::apply(ti::get_old_core(), ti::get_core());
	ti::get().old_core.reset();
	TI_LOG(DEBUG, "core update completed");
}
}; // namespace app
