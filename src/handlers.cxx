#include <handlers.hh>
#include <ti.hh>
#include <update_task.hh>
#include <log.hh>

namespace handlers
{
void signals(boost::asio::signal_set& s, int num)
{
	TI_TRACE();
	switch (num)
	{
		case SIGHUP:
		{
			TI_LOG(INFO, "configuration update required");
			app::ti::get().add_task(std::make_shared<app::update_task>());
			break;
		}
		case SIGKILL:
		{
			TI_LOG(INFO, "SIGKILL was received");
			app::ti::stop();
			break;
		}
		case SIGTERM:
		{
			TI_LOG(INFO, "SIGTERM was received");
			app::ti::stop();
			break;
		}
		case SIGINT:
		{
			TI_LOG(INFO, "SIGINT was received");
			app::ti::stop();
			break;
		}
		default:
		{
			TI_LOG(INFO, "unsupported signal");
			break;
		}
	}

	s.async_wait([&](const boost::system::error_code&, int sig) {
		signals(s, sig);
	});
}
}; // namespace handlers
