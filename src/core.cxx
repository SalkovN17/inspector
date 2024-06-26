#include <core.hh>
#include <log.hh>

namespace app {
core::core()
{
	TI_TRACE();
}

core::~core()
{
	TI_TRACE();
}

void core::run(core& now)
{
	if (now.proxy)
		now.proxy->run();
}

void core::apply(core& old, core& now)
{
	proxy::proxy::apply(old.proxy, now.proxy);
}
}; // namespace app
