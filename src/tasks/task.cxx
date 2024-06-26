#include <ti.hh>
#include <log.hh>

#include <tasks/task.hh>

namespace tasks {

const int task::default_failure_timeout;

task::task(const std::string& name) :
	failure_attempt(0),
	name(name),
	failure_timer(app::ti::get_io())
{
	TI_TRACE();
}

task::task(const std::string& name, boost::asio::io_service& io) :
	failure_attempt(0),
	name(name),
	failure_timer(io)
{
	TI_TRACE();
}

task::~task()
{
	TI_TRACE();
}

void task::set_creator(std::shared_ptr<task_creator> creator)
{
	this->creator = creator;
}

int task::get_failure_timeout() const noexcept
{
	int seconds;
	switch (this->failure_attempt)
	{
		case 1:
			seconds = 60;
			break;
		case 2:
			seconds = 300;
			break;
		case 3:
			seconds = 600;
			break;
		case 4:
			seconds = 900;
			break;
		case 5:
			seconds = 1800;
			break;
		default:
			seconds = task::default_failure_timeout;
			break;
	}

	return seconds;
}

const std::string& task::get_name() const & noexcept
{
	return this->name;
}

int task::get_failure_attempt() const noexcept
{
	return this->failure_attempt;
}

int task::retry()
{
	this->failure_attempt++;
	int timeout = this->get_failure_timeout();
	this->failure_timer.expires_after(std::chrono::seconds(timeout));

	auto t = this->shared_from_this();
	this->failure_timer.async_wait([t](const boost::system::error_code& e) {
		if (e == boost::asio::error::operation_aborted)
			return;

		std::shared_ptr<task_creator> creator = t->creator.lock();
		if (!creator)
			return;

		creator->update(t, task::status::retry);
	});

	this->retry_log(timeout);
	return timeout;
}

void task::start_log()
{
	std::shared_ptr<task_creator> creator = this->creator.lock();
	if (!creator)
		return;

	TI_LOG(DEBUG, "%s start for %s",
	       this->name.c_str(), creator->get_name().c_str());
}

void task::success_finish_log()
{
	std::shared_ptr<task_creator> creator = this->creator.lock();
	if (!creator)
		return;

	TI_LOG(DEBUG, "%s finished with success for %s",
	       this->name.c_str(), creator->get_name().c_str());
}

void task::fail_finish_log(const char * reason)
{
	std::shared_ptr<task_creator> creator = this->creator.lock();
	if (!creator)
		return;

	TI_LOG(DEBUG, "%s failed for %s, because: %s",
	       this->name.c_str(), creator->get_name().c_str(), reason);
}

void task::retry_log(int timeout)
{
	std::shared_ptr<task_creator> creator = this->creator.lock();
	if (!creator)
		return;

	TI_LOG(DEBUG, "%s for %s will be repeated after %i seconds, the number of failure attempts is %i",
	       this->name.c_str(), creator->get_name().c_str(), timeout, this->failure_attempt);
}
}; // namespace tasks
