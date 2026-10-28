/* SPDX-License-Identifier: MPL-2.0 */
// Built with the library's route table at MAX_FLOWS routes, so a test can fill it
#include "mux_proxy_helpers.h"

static const char other_password[] = "abcdefghijabcdefghijabcdefghij";

// Fills the table with routes of CLIENT on ports 5000 and up, each through its own relay port
static juice_agent_t *fill(uint16_t port, int fds[MAX_FLOWS], uint16_t relays[MAX_FLOWS]) {
	const char *ranges[] = {"127.0.0.0/8"};
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, ranges, 1) == 0);
	juice_agent_t *agent = test_mux_agent(port, true);
	for (int i = 0; i < MAX_FLOWS; ++i) {
		fds[i] = test_socket(&relays[i]);
		send_signed(fds[i], port, CLIENT, (uint16_t)(5000 + i), test_password);
		test_response(fds[i]);
	}
	return agent;
}

static void clear(uint16_t port, int fds[MAX_FLOWS]) {
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, NULL, 0) == 0);
	for (int i = 0; i < MAX_FLOWS; ++i) close(fds[i]);
}

// Relay ports that keep talking keep the routes of clients that left, as an attacker could
static void gives_up_the_oldest_dead_route_when_full(void) {
	uint16_t port = test_port(), relays[MAX_FLOWS], fresh;
	int fds[MAX_FLOWS];
	juice_destroy(fill(port, fds, relays));
	for (int i = 0; i < MAX_FLOWS; ++i) send_relayed(fds[i], port, NULL, 0, "keep", 4);

	juice_agent_t *next = test_mux_agent_with(port, true, other_password);
	int fd = test_socket(&fresh);
	send_signed(fd, port, CLIENT, 6000, other_password);
	test_response_for(fd, other_password);
	assert_relay(port, 6000, fresh);
	assert_relay(port, 5000, 0);
	for (int i = 1; i < MAX_FLOWS; ++i) assert_relay(port, (uint16_t)(5000 + i), relays[i]);

	juice_destroy(next);
	clear(port, fds);
	close(fd);
}

// Taking over a dead route's own relay port leaves the table no fuller, so nothing else goes
static void hands_a_dead_route_port_on_when_full(void) {
	uint16_t port = test_port(), relays[MAX_FLOWS];
	int fds[MAX_FLOWS];
	juice_destroy(fill(port, fds, relays));

	juice_agent_t *next = test_mux_agent_with(port, true, other_password);
	send_signed(fds[1], port, CLIENT, 6000, other_password);
	test_response_for(fds[1], other_password);
	assert_relay(port, 6000, relays[1]);
	assert_relay(port, 5001, 0);
	assert_relay(port, 5000, relays[0]);

	juice_destroy(next);
	clear(port, fds);
}

static void refuses_a_client_when_every_route_lives(void) {
	uint16_t port = test_port(), relays[MAX_FLOWS], fresh;
	int fds[MAX_FLOWS];
	juice_agent_t *agent = fill(port, fds, relays);

	int fd = test_socket(&fresh);
	send_signed(fd, port, CLIENT, 6000, test_password);
	assert(!test_answered(fd));
	assert_relay(port, 6000, 0);
	for (int i = 0; i < MAX_FLOWS; ++i) assert_relay(port, (uint16_t)(5000 + i), relays[i]);

	juice_destroy(agent);
	clear(port, fds);
	close(fd);
}

int main(void) {
	juice_set_log_level(JUICE_LOG_LEVEL_FATAL);
	gives_up_the_oldest_dead_route_when_full();
	hands_a_dead_route_port_on_when_full();
	refuses_a_client_when_every_route_lives();
	return 0;
}
