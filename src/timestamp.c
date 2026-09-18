/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "timestamp.h"

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601 // Match the minimum supported by socket.h (Windows 7)
#endif
#include <windows.h>
#else
#include <time.h>

// clock_gettime() is not implemented on older versions of OS X (< 10.12).
// Use its monotonic Mach clock, never a wall-clock substitute.
#if defined(__APPLE__) && !defined(CLOCK_MONOTONIC)
#include <mach/mach_time.h>
#define JUICE_USE_MACH_CLOCK 1
#endif // defined(__APPLE__) && !defined(CLOCK_MONOTONIC)

#endif

timestamp_t current_timestamp() {
#ifdef _WIN32
	return (timestamp_t)GetTickCount64();
#elif defined(JUICE_USE_MACH_CLOCK)
	mach_timebase_info_data_t timebase;
	if (mach_timebase_info(&timebase) != 0 || timebase.denom == 0)
		return 0;
	// Floating-point conversion avoids overflowing an intermediate integer
	// product on long-running systems with a nontrivial Mach timebase ratio.
	return (timestamp_t)((long double)mach_absolute_time() * timebase.numer /
	                     timebase.denom / 1000000.0L);
#else // POSIX
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;
	return (timestamp_t)ts.tv_sec * 1000 + (timestamp_t)ts.tv_nsec / 1000000;
#endif
}
