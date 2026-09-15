/* SPDX-License-Identifier: MPL-2.0 */
#include "udp_send_limits.h"
#include <limits.h>
#include <string.h>

uint64_t juice_monotonic_time_ms(void) {
	timestamp_t now = current_timestamp();
	return now < 0 ? UINT64_MAX : (uint64_t)now;
}

int juice_set_udp_send_limits(juice_agent_t *agent, const juice_udp_send_limits_t *input) {
	if (!agent || !input || agent->conn_impl || agent->udp_send_limited ||
	    agent->config.concurrency_mode != JUICE_CONCURRENCY_MODE_MUX ||
	    agent->ice_tcp_mode != JUICE_ICE_TCP_MODE_NONE || agent->config.turn_servers_count ||
	    !input->max_datagrams || !input->max_payload_bytes || input->max_payload_bytes > 65507 ||
	    input->deadline_monotonic_ms > INT64_MAX ||
	    input->deadline_monotonic_ms <= juice_monotonic_time_ms() ||
	    ((input->destination_address != NULL) != (input->destination_port != 0)))
		return JUICE_ERR_INVALID;
	addr_record_t destination = {0};
	destination.socktype = SOCK_DGRAM;
	if (input->destination_address) {
		struct sockaddr_in *v4 = (struct sockaddr_in *)&destination.addr;
		struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&destination.addr;
		if (inet_pton(AF_INET, input->destination_address, &v4->sin_addr) == 1) {
			v4->sin_family = AF_INET; v4->sin_port = htons(input->destination_port);
			destination.len = sizeof(*v4);
		} else if (inet_pton(AF_INET6, input->destination_address, &v6->sin6_addr) == 1 &&
		           !IN6_IS_ADDR_V4MAPPED(&v6->sin6_addr)) {
			v6->sin6_family = AF_INET6; v6->sin6_port = htons(input->destination_port);
			destination.len = sizeof(*v6);
		} else return JUICE_ERR_INVALID;
		if (addr_is_any((struct sockaddr *)&destination.addr)) return JUICE_ERR_INVALID;
	}
	// No callbacks may race configuration before gathering (same rule as ICE attributes).
	if (mutex_init(&agent->udp_send_mutex, MUTEX_PLAIN)) return JUICE_ERR_FAILED;
	agent->udp_send_limits = *input;
	agent->udp_send_limits.destination_address = NULL; // Never retain borrowed strings.
	agent->udp_send_destination = destination;
	agent->udp_send_limited = true;
	return JUICE_ERR_SUCCESS;
}

int juice_get_udp_send_stats(juice_agent_t *agent, juice_udp_send_stats_t *stats) {
	if (!agent || !stats) return JUICE_ERR_INVALID;
	if (!agent->udp_send_limited) return JUICE_ERR_NOT_AVAIL;
	mutex_lock(&agent->udp_send_mutex);
	*stats = agent->udp_send_stats;
	mutex_unlock(&agent->udp_send_mutex);
	return JUICE_ERR_SUCCESS;
}

bool udp_send_reserve(juice_agent_t *agent, const addr_record_t *dst, size_t size) {
	if (!agent->udp_send_limited) return true;
	mutex_lock(&agent->udp_send_mutex);
	juice_udp_send_rejection_t rejection = JUICE_UDP_SEND_NOT_REJECTED;
	if (juice_monotonic_time_ms() >= agent->udp_send_limits.deadline_monotonic_ms)
		rejection = JUICE_UDP_SEND_EXPIRED;
	else if (dst->socktype != SOCK_DGRAM || (dst->addr.ss_family != AF_INET && dst->addr.ss_family != AF_INET6))
		rejection = JUICE_UDP_SEND_UNSUPPORTED;
	else if (agent->udp_send_destination.len && !addr_record_is_equal(&agent->udp_send_destination, dst, true))
		rejection = JUICE_UDP_SEND_DESTINATION;
	else if (size > agent->udp_send_limits.max_payload_bytes)
		rejection = JUICE_UDP_SEND_SIZE;
	else if (agent->udp_send_stats.reserved_datagrams >= agent->udp_send_limits.max_datagrams)
		rejection = JUICE_UDP_SEND_COUNT;
	if (rejection != JUICE_UDP_SEND_NOT_REJECTED) {
		if (agent->udp_send_stats.rejected_datagrams != UINT64_MAX) ++agent->udp_send_stats.rejected_datagrams;
		agent->udp_send_stats.last_rejection = rejection;
		mutex_unlock(&agent->udp_send_mutex);
		return false;
	}
	++agent->udp_send_stats.reserved_datagrams;
	return true;
}

void udp_send_finish(juice_agent_t *agent, int result) {
	if (!agent->udp_send_limited) return;
	if (result >= 0) {
		++agent->udp_send_stats.sent_datagrams;
		agent->udp_send_stats.sent_bytes += (uint64_t)result;
	}
	mutex_unlock(&agent->udp_send_mutex);
}
