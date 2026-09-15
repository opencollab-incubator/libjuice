/* SPDX-License-Identifier: MPL-2.0 */
#ifndef JUICE_UDP_SEND_LIMITS_H
#define JUICE_UDP_SEND_LIMITS_H
#include "agent.h"

// Caller already owns the mux socket send mutex. Success holds the agent budget
// mutex until finish. No library callback or registry lock is acquired here.
bool udp_send_reserve(juice_agent_t *agent, const addr_record_t *dst, size_t size);
void udp_send_finish(juice_agent_t *agent, int result);
#endif
