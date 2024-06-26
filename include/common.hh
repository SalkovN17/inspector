#include <string>

namespace app {
enum time_constants
{
	seconds_per_minute = 60,
	minutes_per_hour   = 60,
	hours_per_day      = 24,
	days_per_year      = 365,
	seconds_per_day    = hours_per_day * minutes_per_hour * seconds_per_minute,
	seconds_per_year   = days_per_year * seconds_per_day,
};
std::pair<std::string, std::string> get_host_and_port_from_url(const std::string &url);
std::string get_date_after(int seconds);
}; // namespace app
