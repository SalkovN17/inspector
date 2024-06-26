#pragma once

#include <log.hh>

#include <string>
#include <map>
#include <memory>
#include <list>
#include <algorithm>

namespace app {
template <typename K, class V>
class table
{
protected:
	std::string name;
	std::map<K, std::shared_ptr<V>> map;
public:
	table(const std::string& name) : name(name)
	{
		TI_TRACE();
	}

	virtual ~table()
	{
		TI_TRACE();
	}

	void add(K key, V * val)
	{
		this->map[key] = std::shared_ptr<V>(val);
	}

	std::shared_ptr<V>& lookup(const K key) &
	{
		return this->map.at(key);
	}

	auto& get() & noexcept
	{
		return this->map;
	}

	static auto get_added(const decltype(table::map)& old,
	                      const decltype(table::map)& now)
	{
		std::list<std::pair<K, std::shared_ptr<V>>> added;
		std::set_difference(now.begin(), now.end(),
		                    old.begin(), old.end(),
		                    std::inserter(added, added.begin()),
		                                  [](const auto& a, const auto& b) {
		                                      return a.first < b.first;
		                                  });
		return added;
	}

	static auto get_removed(const decltype(table::map)& old,
	                        const decltype(table::map)& now)
	{
		std::list<std::pair<K, std::shared_ptr<V>>> removed;
		std::set_difference(old.begin(), old.end(),
		                    now.begin(), now.end(),
		                    std::inserter(removed, removed.begin()),
		                                  [](const auto& a, const auto& b) {
		                                      return a.first < b.first;
		                                  });
		return removed;
	}

	static auto get_existed(const decltype(table::map)& old,
	                        const decltype(table::map)& now)
	{
		std::list<std::pair<K, std::shared_ptr<V>>> existed;
		std::set_intersection(old.begin(), old.end(),
		                      now.begin(), now.end(),
		                      std::inserter(existed, existed.begin()),
		                                    [](const auto& a, const auto& b) {
		                                        return a.first < b.first;
		                                    });

		return existed;
	}
};
}; // namespace namespace app
