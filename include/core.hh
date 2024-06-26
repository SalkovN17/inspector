#pragma once

#include <proxy/proxy.hh>

namespace app {
class core
{
public:
	static void run(core& now);
	static void apply(core& old, core& now);

	std::shared_ptr<proxy::proxy> proxy;

	core();
	~core();
};
}; // namespace app
