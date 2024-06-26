
#pragma once

#include <tasks/task.hh>

#include <boost/asio.hpp>
#include <string>
#include <list>

namespace tasks {

class task;

class task_creator : public std::enable_shared_from_this<task_creator>
{
private:
	std::string name;
	boost::asio::io_service& io;

	std::mutex mutex;
	std::list<std::shared_ptr<task>> tasks;
	std::list<std::shared_ptr<task>> failed_tasks;

	void del_task(std::shared_ptr<task> t);
	void del_failed_task(std::shared_ptr<task> t);
	void add_task();
	void post_to_io(std::shared_ptr<task> t);
public:
	task_creator() = delete;
	task_creator(const std::string& name, boost::asio::io_service& io);
	virtual ~task_creator();

	void add_task(std::shared_ptr<task> t);
	void update(std::shared_ptr<task> t, task::status status);
	const std::string& get_name() const & noexcept;
};
}; // namespace tasks
