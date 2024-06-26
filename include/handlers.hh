#pragma once

#include <boost/asio.hpp>

namespace handlers
{
	void signals(boost::asio::signal_set& s, int num);
}; // namespace handlers
