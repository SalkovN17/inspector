#pragma once

#include <tasks/task.hh>

namespace app {

class update_task final : public tasks::task
{
public:
	update_task();
	~update_task();
	void perform() override;
};
}; // namespace app
