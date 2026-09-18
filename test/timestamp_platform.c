/* SPDX-License-Identifier: MPL-2.0 */
#include "timestamp.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

// Compile the actual timestamp.c platform branch against minimal SDK shims.
// These cover clock width/conversion; they are not native Windows/macOS runs.
static uint64_t ticks;
#ifdef _WIN32
uint64_t GetTickCount64(void) { return ticks; }
#else
#include <mach/mach_time.h>
uint64_t mach_absolute_time(void) { return ticks; }
int mach_timebase_info(mach_timebase_info_data_t *info) {
	info->numer = 125;
	info->denom = 3;
	return 0;
}
#endif

int main(void) {
#ifdef _WIN32
	ticks = UINT32_MAX - 5;
	timestamp_t before = current_timestamp();
	ticks += 20;
	assert(current_timestamp() - before == 20);
	assert(current_timestamp() > UINT32_MAX);
	puts("Windows timestamp: full 64-bit uptime survives DWORD boundary PASS (SDK shim)");
#else
	ticks = 24000;
	assert(current_timestamp() == 1);
	ticks = UINT64_C(24000) * UINT64_C(500000000000);
	timestamp_t before = current_timestamp();
	assert(before == INT64_C(500000000000));
	ticks += 24000;
	assert(current_timestamp() - before == 1);
	puts("Legacy Mach timestamp: monotonic ticks and long-uptime ratio conversion PASS (SDK shim)");
#endif
	return 0;
}
