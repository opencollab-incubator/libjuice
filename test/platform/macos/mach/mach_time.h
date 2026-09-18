/* SPDX-License-Identifier: MPL-2.0 */
#ifndef JUICE_TEST_MACH_TIME_H
#define JUICE_TEST_MACH_TIME_H
#include <stdint.h>
typedef struct {
	uint32_t numer;
	uint32_t denom;
} mach_timebase_info_data_t;
uint64_t mach_absolute_time(void);
int mach_timebase_info(mach_timebase_info_data_t *info);
#endif
