#pragma once

#include <stdio.h>

#define TI_LOG(mnemonic, ...) do { \
	char _ti_buf[snprintf(nullptr, 0, __VA_ARGS__) + 1]; \
	snprintf(_ti_buf, sizeof(_ti_buf), __VA_ARGS__); \
	printf("%s\n", _ti_buf); \
} while(0)
#define TI_TRACE(...)
#define TI_PRINT(...)
