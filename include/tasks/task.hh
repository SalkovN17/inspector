#pragma once

#include <tasks/task_creator.hh>
#include <boost/asio.hpp>

namespace tasks {

class task_creator;

class task : public std::enable_shared_from_this<task>
{
private:
	int failure_attempt;

	int get_failure_timeout() const noexcept;
protected:
	std::string name;
	boost::asio::steady_timer failure_timer;
	std::weak_ptr<task_creator> creator;

	struct perform_lambda
	{
		std::weak_ptr<task> t;

		perform_lambda() = delete;
		perform_lambda(std::shared_ptr<task> t) : t(t) {}
		void operator()()
		{
			auto st = this->t.lock();
			if (!st)
				return;

			st->perform();
		}
	};

	void start_log();
	void success_finish_log();
	void fail_finish_log(const char * reason);
	void retry_log(int timeout);
public:
	static const int default_failure_timeout = 3600;

	enum class status {fail, success, retry};

	task() = delete;
	task(const std::string& name);
	task(const std::string& name, boost::asio::io_service& io);
	virtual ~task();

	void set_creator(std::shared_ptr<task_creator> creator);
	virtual void perform() = 0;
	int retry();

	int get_failure_attempt() const noexcept;
	const std::string& get_name() const & noexcept;
};
}; // namespace tasks
