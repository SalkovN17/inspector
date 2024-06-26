#include <tasks/task_creator.hh>
#include <tasks/task.hh>
#include <log.hh>

#include <doctest.h>

#include <thread>
#include <boost/thread.hpp>

namespace tasks
{
task_creator::task_creator(const std::string& name, boost::asio::io_service& io) :
	name(name),
	io(io)
{
	TI_TRACE();
}

task_creator::~task_creator()
{
	TI_TRACE();
}

const std::string& task_creator::get_name() const & noexcept
{
	return this->name;
}

void task_creator::post_to_io(std::shared_ptr<task> t)
{
	boost::asio::post(this->io, [t](){
		t->perform();
	});
}

void task_creator::add_task()
{
	if (this->tasks.size() == 0)
		return;
	else
		this->post_to_io(this->tasks.front());
}

void task_creator::add_task(std::shared_ptr<task> t)
{
	std::lock_guard<std::mutex> lock(this->mutex);
	t->set_creator(this->shared_from_this());

	this->tasks.push_back(t);
	if (this->tasks.size() == 1)
		this->post_to_io(t);
}

void task_creator::del_task(std::shared_ptr<task> t)
{
	this->tasks.remove_if([&](const std::shared_ptr<task> &el) {
		return el == t;
	});
}

void task_creator::del_failed_task(std::shared_ptr<task> t)
{
	this->failed_tasks.remove_if([&](const std::shared_ptr<task> &el) {
		return el == t;
	});
}

void task_creator::update(std::shared_ptr<task> t, task::status status)
{
	std::lock_guard<std::mutex> lock(this->mutex);
	switch (status)
	{
		case task::status::fail:
		{
			this->del_task(t);
			this->failed_tasks.push_back(t);
			t->retry();
			break;
		}
		case task::status::retry:
			this->del_failed_task(t);
			this->tasks.push_front(t);
			break;
		case task::status::success:
			this->del_task(t);
			break;
		default:
			break;
	}

	this->add_task();
}

class test_task : public task
{
public:
	int& num;
	boost::asio::io_service& ios;

	test_task(int& num, boost::asio::io_service& ios) :
		task("test_task", ios), num(num), ios(ios) {}
	void perform() override
	{
		std::shared_ptr<task_creator> creator = this->creator.lock();
		if (!creator)
			return;

		std::this_thread::sleep_for(std::chrono::milliseconds(20));

		this->num++;
		creator->update(this->shared_from_this(), task::status::success);
	}
};

TEST_CASE("[tasks]task_creator")
{
	boost::asio::io_service io;
	std::shared_ptr<task_creator> creator = std::make_shared<task_creator>("test_creator", io);

	SUBCASE("checking deletion of creator after task has started execution")
	{
		int num = 0;
		creator->add_task(std::make_shared<test_task>(num, io));
		creator->add_task(std::make_shared<test_task>(num, io));

		boost::thread_group io_threads;
		io_threads.create_thread(boost::bind(&boost::asio::io_service::poll, &io));
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		creator.reset();

		io_threads.join_all();

		CHECK(num == 1);
	}

	SUBCASE("checking deletion of creator before task has started execution")
	{
		int num = 0;
		creator->add_task(std::make_shared<test_task>(num, io)); // -V614
		creator->add_task(std::make_shared<test_task>(num, io));
		creator.reset();
		io.poll();
		CHECK(num == 0);
	}

	SUBCASE("checking task failure timeouts")
	{
		int num = 0;
		auto t = std::make_shared<test_task>(num, io);

		int expected_failure_attempt = 1;

		CHECK(t->retry() == 60);
		CHECK(t->get_failure_attempt() == expected_failure_attempt++);

		CHECK(t->retry() == 300);
		CHECK(t->get_failure_attempt() == expected_failure_attempt++);

		CHECK(t->retry() == 600);
		CHECK(t->get_failure_attempt() == expected_failure_attempt++);

		CHECK(t->retry() == 900);
		CHECK(t->get_failure_attempt() == expected_failure_attempt++);

		CHECK(t->retry() == 1800);
		CHECK(t->get_failure_attempt() == expected_failure_attempt++);

		CHECK(t->retry() == task::default_failure_timeout);
		CHECK(t->get_failure_attempt() == expected_failure_attempt++);

		CHECK(t->retry() == task::default_failure_timeout);
		CHECK(t->get_failure_attempt() == expected_failure_attempt++);

		CHECK(t->retry() == task::default_failure_timeout);
		CHECK(t->get_failure_attempt() == expected_failure_attempt++);
	}
}
}; // namespace tasks
