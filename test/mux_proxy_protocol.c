/* SPDX-License-Identifier: MPL-2.0 */
#include "mux_proxy_helpers.h"
#include <time.h>

typedef struct observed {
	atomic_uint calls;
	atomic_uint_fast64_t id;
	char address[64];
	uint16_t port;
} observed_t;

static void incoming(const juice_mux_pending_request_t *request, void *ptr) {
	observed_t *observed = ptr;
	snprintf(observed->address, sizeof(observed->address), "%s", request->binding.address);
	observed->port = request->binding.port;
	atomic_store(&observed->id, request->request_id);
	atomic_fetch_add(&observed->calls, 1);
}

static uint64_t await_callback(observed_t *observed, unsigned int count) {
	for (int i = 0; i < 400 && atomic_load(&observed->calls) < count; ++i) usleep(5000);
	assert(atomic_load(&observed->calls) == count);
	return atomic_load(&observed->id);
}

static void send_binding(int fd, uint16_t port, const char *client) {
	send_signed(fd, port, client, 5555, test_password);
}

// Waits for a check the agent sends on its own, a binding request
static bool await_check(int fd, int timeout_ms) {
	for (int waited = 0; waited < timeout_ms; waited += 50) {
		struct pollfd pfd = {.fd = fd, .events = POLLIN};
		assert(poll(&pfd, 1, 50) >= 0);
		if (!(pfd.revents & POLLIN)) continue;
		unsigned char datagram[2048];
		ssize_t size = recv(fd, datagram, sizeof(datagram), 0);
		stun_message_t message = {0};
		if (size > 0 && _juice_stun_read(datagram, size, &message) > 0 &&
		    message.msg_class == STUN_CLASS_REQUEST)
			return true;
	}
	return false;
}

static void attributes_a_relayed_client(void) {
	uint16_t port = test_port(), relay;
	int fd = test_socket(&relay);
	const char *relays[] = {"127.0.0.0/8"};
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, relays, 1) == 0);
	observed_t observed = {0};
	assert(juice_mux_listen_pending("127.0.0.1", port, NULL, incoming, &observed) == 0);

	send_binding(fd, port, CLIENT);
	uint64_t id = await_callback(&observed, 1);
	assert(strcmp(observed.address, CLIENT) == 0 && observed.port == 5555);
	assert(juice_mux_verify_request("127.0.0.1", port, id, test_password) == 0);
	juice_agent_t *agent = test_agent(port);
	assert(juice_mux_attach_request("127.0.0.1", port, id, agent) == 0);
	// Sent to the client, so it only arrives here if it went back through the relay
	test_response(fd);

	juice_mux_stats_t stats = test_received(port, 1);
	assert(stats.mapped_tuples == 1);
	// A relay that only prefixes the first datagram keeps its client
	send_binding(fd, port, NULL);
	stats = test_received(port, 2);
	test_response(fd);
	assert(stats.notifications == 1 && atomic_load(&observed.calls) == 1);

	// So does a new list that still has the relay, while one without it forgets the client
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, relays, 1) == 0);
	send_binding(fd, port, NULL);
	test_response(fd);
	const char *others[] = {"10.0.0.0/8"};
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, others, 1) == 0);
	send_binding(fd, port, NULL);
	assert(!test_answered(fd));

	assert(juice_mux_listen_pending("127.0.0.1", port, NULL, NULL, NULL) == 0);
	juice_destroy(agent);
	// The setting alone holds the endpoint open
	assert(juice_mux_get_stats("127.0.0.1", port, &stats) == 0);
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, NULL, 0) == 0);
	assert(juice_mux_get_stats("127.0.0.1", port, &stats) == JUICE_ERR_NOT_AVAIL);
	close(fd);
}

// A dual-stack relay declares an IPv4 client as v4-mapped IPv6, which arrives as the IPv4 client
static void unmaps_a_v4_mapped_client(void) {
	uint16_t port = test_port(), relay;
	int fd = test_socket(&relay);
	const char *relays[] = {"127.0.0.0/8"};
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, relays, 1) == 0);
	observed_t observed = {0};
	assert(juice_mux_listen_pending("127.0.0.1", port, NULL, incoming, &observed) == 0);

	send_binding(fd, port, "::ffff:" CLIENT);
	await_callback(&observed, 1);
	assert(strcmp(observed.address, CLIENT) == 0 && observed.port == 5555);

	assert(juice_mux_listen_pending("127.0.0.1", port, NULL, NULL, NULL) == 0);
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, NULL, 0) == 0);
	close(fd);
}

// A host can ask which relay a client came through, by the client the header declared
static void names_the_relay_of_a_client(void) {
	uint16_t port = test_port(), relay;
	int fd = test_socket(&relay);
	char found[64], expected[64];
	assert(juice_mux_get_proxy_relay("127.0.0.1", port, CLIENT, 5555, found, sizeof(found)) ==
	       JUICE_ERR_NOT_AVAIL);
	const char *relays[] = {"127.0.0.0/8"};
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, relays, 1) == 0);
	observed_t observed = {0};
	assert(juice_mux_listen_pending("127.0.0.1", port, NULL, incoming, &observed) == 0);

	send_binding(fd, port, CLIENT);
	await_callback(&observed, 1);
	snprintf(expected, sizeof(expected), "127.0.0.1:%u", relay);
	assert(juice_mux_get_proxy_relay("127.0.0.1", port, CLIENT, 5555, found, sizeof(found)) == 0);
	assert(strcmp(found, expected) == 0);
	// The same client written v4-mapped, as a dual-stack caller may
	assert(juice_mux_get_proxy_relay("127.0.0.1", port, "::ffff:" CLIENT, 5555, found,
	                                 sizeof(found)) == 0);
	assert(strcmp(found, expected) == 0);
	// Another port is another client, and a name is never looked up
	assert(juice_mux_get_proxy_relay("127.0.0.1", port, CLIENT, 5556, found, sizeof(found)) ==
	       JUICE_ERR_NOT_AVAIL);
	assert(juice_mux_get_proxy_relay("127.0.0.1", port, "client.example", 5555, found,
	                                 sizeof(found)) == JUICE_ERR_INVALID);
	assert(juice_mux_get_proxy_relay("127.0.0.1", port, CLIENT, 5555, found, 4) ==
	       JUICE_ERR_FAILED);

	assert(juice_mux_listen_pending("127.0.0.1", port, NULL, NULL, NULL) == 0);
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, NULL, 0) == 0);
	assert(juice_mux_get_proxy_relay("127.0.0.1", port, CLIENT, 5555, found, sizeof(found)) ==
	       JUICE_ERR_NOT_AVAIL);
	close(fd);
}

// Peers only come through relays, so the rest is dropped whether it carries a header or not
static void drops_what_no_relay_brings(void) {
	uint16_t port = test_port(), source, relay;
	int fd = test_socket(&source), relay_fd = test_socket(&relay);
	const char *relays[] = {"10.0.0.0/8"};
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, relays, 1) == 0);
	observed_t observed = {0};
	assert(juice_mux_listen_pending("127.0.0.1", port, NULL, incoming, &observed) == 0);

	send_binding(fd, port, CLIENT);
	send_binding(fd, port, NULL);
	juice_mux_stats_t stats = test_received(port, 2);
	usleep(30000);
	assert(atomic_load(&observed.calls) == 0);
	assert(juice_mux_get_stats("127.0.0.1", port, &stats) == 0 && stats.rejected == 2);

	// Nor does a relay's datagram without a header, before any flow says whose it is
	const char *local[] = {"127.0.0.0/8"};
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, local, 1) == 0);
	send_binding(relay_fd, port, NULL);
	stats = test_received(port, 3);
	usleep(30000);
	assert(atomic_load(&observed.calls) == 0);
	assert(juice_mux_get_stats("127.0.0.1", port, &stats) == 0 && stats.rejected == 3);

	assert(juice_mux_listen_pending("127.0.0.1", port, NULL, NULL, NULL) == 0);
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, NULL, 0) == 0);
	close(fd);
	close(relay_fd);
}

// Responses to the endpoint's own requests still come straight from their server
static void keeps_responses_to_its_own_requests(void) {
	uint16_t port = test_port(), server;
	int fd = test_socket(&server);
	const char *relays[] = {"10.0.0.0/8"};
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, relays, 1) == 0);
	juice_config_t config = {0};
	config.concurrency_mode = JUICE_CONCURRENCY_MODE_MUX;
	config.bind_address = "127.0.0.1";
	config.local_port_range_begin = config.local_port_range_end = port;
	config.stun_server_host = "127.0.0.1";
	config.stun_server_port = server;
	juice_agent_t *agent = juice_create(&config);
	assert(agent && juice_gather_candidates(agent) == 0);

	unsigned char datagram[2048];
	struct sockaddr_storage from;
	socklen_t from_size = sizeof(from);
	struct pollfd pfd = {.fd = fd, .events = POLLIN};
	assert(poll(&pfd, 1, 2000) == 1);
	ssize_t size = recvfrom(fd, datagram, sizeof(datagram), 0, (struct sockaddr *)&from, &from_size);
	stun_message_t request = {0};
	assert(size > 0 && _juice_stun_read(datagram, size, &request) > 0);
	stun_message_t response = {0};
	response.msg_class = STUN_CLASS_RESP_SUCCESS;
	response.msg_method = STUN_METHOD_BINDING;
	memcpy(response.transaction_id, request.transaction_id, STUN_TRANSACTION_ID_SIZE);
	struct sockaddr_in *mapped = (struct sockaddr_in *)&response.mapped.addr;
	mapped->sin_family = AF_INET;
	mapped->sin_port = htons(4000);
	assert(inet_pton(AF_INET, "198.51.100.4", &mapped->sin_addr) == 1);
	response.mapped.len = sizeof(struct sockaddr_in);
	int written = _juice_stun_write(datagram, sizeof(datagram), &response, NULL);
	assert(written > 0);
	assert(sendto(fd, datagram, written, 0, (struct sockaddr *)&from, from_size) == written);

	char description[JUICE_MAX_SDP_STRING_LEN];
	bool reflexive = false;
	for (int i = 0; i < 200 && !reflexive; ++i) {
		usleep(10000);
		assert(juice_get_local_description(agent, description, sizeof(description)) == 0);
		reflexive = strstr(description, "typ srflx") != NULL;
	}
	assert(reflexive);
	juice_destroy(agent);
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, NULL, 0) == 0);
	close(fd);
}

// Direct agents with no listener, as built-in signaling runs: the setting alone keeps it served
static void serves_agents_without_a_listener(void) {
	uint16_t port = test_port(), relay;
	int fd = test_socket(&relay);
	const char *relays[] = {"127.0.0.0/8"};
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, relays, 1) == 0);
	// The endpoint idles before its first agent, as between a bind and the first join
	usleep(50000);
	juice_agent_t *agent = test_mux_agent(port, true);
	send_binding(fd, port, CLIENT);
	test_response(fd);
	juice_destroy(agent);

	// Clearing wakes the endpoint rather than waiting out its idle poll
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, NULL, 0) == 0);
	clock_gettime(CLOCK_MONOTONIC, &end);
	assert(end.tv_sec - start.tv_sec < 2);
	close(fd);
}

// A header alone never moves a client's route, nor does a check its agent's password fails
static void keeps_a_route_from_unsigned_headers(void) {
	static const char garbage[] = "not a STUN message";
	uint16_t port = test_port(), relay, other;
	int fd = test_socket(&relay), other_fd = test_socket(&other);
	const char *relays[] = {"127.0.0.0/8"};
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, relays, 1) == 0);
	juice_agent_t *agent = test_mux_agent(port, true);
	send_binding(fd, port, CLIENT);
	test_response(fd);
	assert_relay(port, 5555, relay);

	send_relayed(other_fd, port, CLIENT, 5555, garbage, sizeof(garbage));
	send_signed(other_fd, port, CLIENT, 5555, "wrongwrongwrongwrongwrongwrong");
	test_received(port, 3);
	assert(!test_answered(other_fd));
	assert_relay(port, 5555, relay);
	send_binding(fd, port, NULL);
	test_response(fd);

	juice_destroy(agent);
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, NULL, 0) == 0);
	close(other_fd);
	close(fd);
}

// A client moves to a relay port that brings a check its own agent's password signs
static void moves_a_client_its_agent_authenticates(void) {
	uint16_t port = test_port(), relay, other;
	int fd = test_socket(&relay), other_fd = test_socket(&other);
	const char *relays[] = {"127.0.0.0/8"};
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, relays, 1) == 0);
	juice_agent_t *agent = test_mux_agent(port, true);
	send_binding(fd, port, CLIENT);
	test_response(fd);

	send_binding(other_fd, port, CLIENT);
	test_response(other_fd);
	assert_relay(port, 5555, other);

	juice_destroy(agent);
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, NULL, 0) == 0);
	close(other_fd);
	close(fd);
}

// A check another agent's password signs moves neither a client nor its relay
static void keeps_routes_from_other_agents(void) {
	static const char other_password[] = "abcdefghijabcdefghijabcdefghij";
	uint16_t port = test_port(), relay, other;
	int fd = test_socket(&relay), other_fd = test_socket(&other);
	const char *relays[] = {"127.0.0.0/8"};
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, relays, 1) == 0);
	juice_agent_t *agent = test_mux_agent(port, true);
	juice_agent_t *other_agent = test_mux_agent_with(port, true, other_password);
	send_binding(fd, port, CLIENT);
	test_response(fd);

	// The client's address from elsewhere, and the client's relay port for another client
	send_signed(other_fd, port, CLIENT, 5555, other_password);
	send_signed(fd, port, CLIENT, 6666, other_password);
	juice_mux_stats_t stats = test_received(port, 3);
	assert(!test_answered(other_fd));
	assert_relay(port, 5555, relay);
	assert_relay(port, 6666, 0);
	assert(juice_mux_get_stats("127.0.0.1", port, &stats) == 0 && stats.mapped_tuples == 1);
	send_binding(fd, port, NULL);
	test_response(fd);

	juice_destroy(other_agent);
	juice_destroy(agent);
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, NULL, 0) == 0);
	close(other_fd);
	close(fd);
}

// A relay prefixing only the first datagram has the next ones attributed, though only a check
// that authenticates routes the client
static void attributes_after_a_first_datagram_that_is_not_a_check(void) {
	static const char data[] = "application data";
	uint16_t port = test_port(), relay;
	int fd = test_socket(&relay);
	const char *relays[] = {"127.0.0.0/8"};
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, relays, 1) == 0);
	juice_agent_t *agent = test_mux_agent(port, true);
	send_relayed(fd, port, CLIENT, 5555, data, sizeof(data));
	test_received(port, 1);
	assert_relay(port, 5555, 0);

	send_binding(fd, port, NULL);
	test_response(fd);
	assert_relay(port, 5555, relay);

	juice_destroy(agent);
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, NULL, 0) == 0);
	close(fd);
}

// A relay port passes to the next client once the agent of the one it routed is gone, whether the
// relay declares the next client with every datagram or only the first
static void hands_a_port_on_once_its_client_leaves(void) {
	static const char data[] = "application data";
	static const char second_password[] = "abcdefghijabcdefghijabcdefghij";
	static const char third_password[] = "ABCDEFGHIJABCDEFGHIJABCDEFGHIJ";
	uint16_t port = test_port(), relay;
	int fd = test_socket(&relay);
	const char *relays[] = {"127.0.0.0/8"};
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, relays, 1) == 0);
	juice_agent_t *first = test_mux_agent(port, true);
	send_binding(fd, port, CLIENT);
	test_response(fd);
	juice_destroy(first);

	// Declared by the first datagram only, and never mistaken for the client that left
	juice_agent_t *second = test_mux_agent_with(port, true, second_password);
	send_relayed(fd, port, CLIENT, 6666, data, sizeof(data));
	send_signed(fd, port, NULL, 0, second_password);
	test_response_for(fd, second_password);
	assert_relay(port, 6666, relay);
	assert_relay(port, 5555, 0);
	juice_destroy(second);

	juice_agent_t *third = test_mux_agent_with(port, true, third_password);
	send_signed(fd, port, CLIENT, 7777, third_password);
	test_response_for(fd, third_password);
	assert_relay(port, 7777, relay);
	assert_relay(port, 6666, 0);

	juice_destroy(third);
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, NULL, 0) == 0);
	close(fd);
}

// A client whose relay is dropped from the list is no longer reached at all
static void never_reaches_a_client_straight(void) {
	uint16_t port = test_port(), relay, client;
	int fd = test_socket(&relay), client_fd = test_socket(&client);
	const char *relays[] = {"127.0.0.0/8"};
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, relays, 1) == 0);
	juice_agent_t *agent = test_mux_agent(port, true);
	send_signed(fd, port, "127.0.0.1", client, test_password);
	test_response(fd);
	// The agent's own check of the client goes through the relay, and retries without an answer
	assert(await_check(fd, 1000));

	const char *others[] = {"10.0.0.0/8"};
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, others, 1) == 0);
	assert(!await_check(client_fd, 1500));

	juice_destroy(agent);
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, NULL, 0) == 0);
	close(client_fd);
	close(fd);
}

// Nor is a candidate the client signaled checked straight, which would show it this endpoint
static void never_checks_a_signaled_candidate_straight(void) {
	uint16_t port = test_port(), client;
	int client_fd = test_socket(&client);
	const char *relays[] = {"10.0.0.0/8"};
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, relays, 1) == 0);
	juice_config_t config = {0};
	config.concurrency_mode = JUICE_CONCURRENCY_MODE_MUX;
	config.mux_direct = true;
	config.bind_address = "127.0.0.1";
	config.local_port_range_begin = config.local_port_range_end = port;
	juice_agent_t *agent = juice_create(&config);
	assert(agent);
	char description[256];
	snprintf(description, sizeof(description),
	         "a=ice-ufrag:peer\r\na=ice-pwd:012345678901234567890123456789\r\n"
	         "a=candidate:1 1 UDP 2122317823 127.0.0.1 %u typ host\r\n",
	         client);
	assert(juice_set_remote_description(agent, description) == 0);
	assert(juice_gather_candidates(agent) == 0);
	assert(!await_check(client_fd, 1500));

	juice_destroy(agent);
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, NULL, 0) == 0);
	close(client_fd);
}

static void refuses_an_invalid_range(void) {
	uint16_t port = test_port();
	const char *word[] = {"relay"};
	const char *prefix[] = {"10.0.0.0/33"};
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, word, 1) == JUICE_ERR_INVALID);
	assert(juice_mux_set_proxy_protocol("127.0.0.1", port, prefix, 1) == JUICE_ERR_INVALID);
	juice_mux_stats_t stats;
	assert(juice_mux_get_stats("127.0.0.1", port, &stats) == JUICE_ERR_NOT_AVAIL);
}

int main(void) {
	juice_set_log_level(JUICE_LOG_LEVEL_FATAL);
	attributes_a_relayed_client();
	unmaps_a_v4_mapped_client();
	names_the_relay_of_a_client();
	drops_what_no_relay_brings();
	keeps_responses_to_its_own_requests();
	serves_agents_without_a_listener();
	keeps_a_route_from_unsigned_headers();
	moves_a_client_its_agent_authenticates();
	keeps_routes_from_other_agents();
	attributes_after_a_first_datagram_that_is_not_a_check();
	hands_a_port_on_once_its_client_leaves();
	never_reaches_a_client_straight();
	never_checks_a_signaled_candidate_straight();
	refuses_an_invalid_range();
	puts("mux PROXY protocol: relayed clients and their relays, kept across lists, the rest "
	     "dropped except STUN responses, served without a listener, routes only moved by "
	     "authenticated checks, ports handed on once their client leaves, nothing sent straight "
	     "but STUN lookups PASS");
}
