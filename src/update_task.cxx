#include <ti.hh>
#include <update_task.hh>
#include <log.hh>

namespace app {

update_task::update_task() :
	task("core updating")
{
	TI_TRACE();
}

update_task::~update_task()
{
	TI_TRACE();
}

void update_task::perform()
{
	std::shared_ptr<tasks::task_creator> creator = this->creator.lock();
	if (!creator)
		return;

	ti::update_core();
	creator->update(this->shared_from_this(), task::status::success);
}
}; // namespace app
