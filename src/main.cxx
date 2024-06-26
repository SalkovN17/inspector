#define DOCTEST_CONFIG_IMPLEMENT
#include <ti.hh>
#include <log.hh>

#include <experimental/filesystem>

#include <doctest.h>

namespace fs = std::experimental::filesystem;

int main(int argc, char **argv)
{
	doctest::Context context;
	context.applyCommandLine(argc, argv);
	context.setOption("npf", true);
	int res = context.run();

	if (context.shouldExit())
		return res;

	opterr = 0;

	std::string config_file = app::ti::default_config_file;
	for (int opt = 0; opt != -1; opt = getopt(argc, argv, "c:v"))
	{
		switch (opt)
		{
			case 'c':
				config_file = std::string(optarg);
				break;
			case 'v':
				TI_LOG(DEBUG, "show version :)");
				return 0;
		}
	}

	if (config_file.empty())
	{
		TI_LOG(DEBUG, "config file isn't set, using default");
		config_file = app::ti::default_config_file;
	}

	if (!fs::exists(config_file))
	{
		TI_LOG(ERR, "config file '%s' not exist", config_file.c_str());
		return -1;
	}

	TI_LOG(INFO, "start with config file '%s'", config_file.c_str());

	try
	{
		app::ti::init(config_file);
		app::ti::run();
	}
	catch(const std::exception& e)
	{
		TI_LOG(ERR, "caught critical exception: %s", e.what());
	}
	catch(...)
	{
		TI_LOG(ERR, "caught unhandled exception, exiting");
	}

	TI_LOG(DEBUG, "deinit");
	app::ti::deinit();

	TI_LOG(DEBUG, "bye");
	return 0;
}
