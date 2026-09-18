/* SPDX-License-Identifier: MPL-2.0 */
#include <juice/juice.h>
#include "stun.h"
#include "thread.h"

// Keep test operations inside assertions active in Release builds too.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static mutex_t received_mutex = MUTEX_INITIALIZER;

static void sleep_ms(unsigned int ms) {
#ifdef _WIN32
	Sleep(ms);
#else
	usleep(ms * 1000);
#endif
}

static uint16_t socket_port(const struct sockaddr *address) {
	return address->sa_family == AF_INET
	           ? ntohs(((const struct sockaddr_in *)address)->sin_port)
	           : ntohs(((const struct sockaddr_in6 *)address)->sin6_port);
}

static socket_t bound_socket(int family, uint16_t *port) {
	socket_t fd = socket(family, SOCK_DGRAM, 0);
	assert(fd != INVALID_SOCKET);
	struct sockaddr_storage storage = {0};
	socklen_t len;
	if (family == AF_INET) {
		struct sockaddr_in *address = (struct sockaddr_in *)&storage;
		address->sin_family = family;
		address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		len = sizeof(*address);
	} else {
		struct sockaddr_in6 *address = (struct sockaddr_in6 *)&storage;
		address->sin6_family = family;
		address->sin6_addr = in6addr_loopback;
		len = sizeof(*address);
	}
	assert(bind(fd, (struct sockaddr *)&storage, len) == 0);
	assert(getsockname(fd, (struct sockaddr *)&storage, &len) == 0);
	*port = socket_port((struct sockaddr *)&storage);
	return fd;
}

static stun_message_t request(socket_t fd, addr_record_t *source, uint16_t mux_port, int timeout_ms) {
	struct pollfd pfd = {.fd = fd, .events = POLLIN};
	assert(poll(&pfd, 1, timeout_ms) == 1);
	unsigned char data[2048];
	source->len = sizeof(source->addr);
	int size = (int)recvfrom(fd, (char *)data, (int)sizeof(data), 0, (struct sockaddr *)&source->addr, &source->len);
	assert(size > 0);
	source->socktype = SOCK_DGRAM;
	assert(socket_port((struct sockaddr *)&source->addr) == mux_port);
	stun_message_t message = {0};
	assert(_juice_stun_read(data, (size_t)size, &message) > 0);
	assert(message.msg_class == STUN_CLASS_REQUEST && message.msg_method == STUN_METHOD_BINDING);
	assert(!message.has_integrity && !message.credentials.username[0]);
	return message;
}

static void respond(socket_t fd, const addr_record_t *source, const stun_message_t *request,
                    int family, uint16_t mapped_port, unsigned int error) {
	stun_message_t response = {0};
	response.msg_class = error ? STUN_CLASS_RESP_ERROR : STUN_CLASS_RESP_SUCCESS;
	response.msg_method = STUN_METHOD_BINDING;
	response.error_code = error;
	memcpy(response.transaction_id, request->transaction_id, STUN_TRANSACTION_ID_SIZE);
	if (mapped_port) {
		response.mapped.socktype = SOCK_DGRAM;
		if (family == AF_INET) {
			struct sockaddr_in *address = (struct sockaddr_in *)&response.mapped.addr;
			address->sin_family = family;
			address->sin_port = htons(mapped_port);
			assert(inet_pton(family, "198.51.100.10", &address->sin_addr) == 1);
			response.mapped.len = sizeof(*address);
		} else {
			struct sockaddr_in6 *address = (struct sockaddr_in6 *)&response.mapped.addr;
			address->sin6_family = family;
			address->sin6_port = htons(mapped_port);
			assert(inet_pton(family, "2001:db8::10", &address->sin6_addr) == 1);
			response.mapped.len = sizeof(*address);
		}
	}
	unsigned char data[2048];
	int size = _juice_stun_write(data, sizeof(data), &response, NULL);
	assert(size > 0);
	assert(sendto(fd, (const char *)data, size, 0, (const struct sockaddr *)&source->addr, source->len) == size);
}

static juice_stun_binding_t snapshot(juice_agent_t *agent) {
	juice_stun_binding_t binding;
	assert(juice_get_stun_binding(agent, 0, &binding) == 0);
	return binding;
}

static juice_stun_binding_t successes(juice_agent_t *agent, uint64_t count) {
	juice_stun_binding_t binding = snapshot(agent);
	for (int i = 0; i < 400 && binding.successful_responses < count; ++i) {
		sleep_ms(5);
		binding = snapshot(agent);
	}
	assert(binding.successful_responses == count);
	assert(binding.state == JUICE_STUN_BINDING_SUCCEEDED);
	assert(binding.last_success_age_ms < 2000);
	return binding;
}

static void unexpected_peer(const juice_mux_pending_request_t *request, void *ptr) {
	(void)request;
	(void)ptr;
	assert(!"STUN discovery must not allocate an incoming peer");
}

static void received(juice_agent_t *agent, const char *data, size_t size, void *ptr) {
	(void)agent;
	assert(size == 4 && memcmp(data, "data", 4) == 0);
	mutex_lock(&received_mutex);
	++*(unsigned int *)ptr;
	mutex_unlock(&received_mutex);
}

static void round_trip(juice_agent_t *first, juice_agent_t *second,
                       unsigned int *first_received, unsigned int *second_received, unsigned int count) {
	assert(juice_send(first, "data", 4) == 0 && juice_send(second, "data", 4) == 0);
	for (int i = 0; i < 400; ++i) {
		mutex_lock(&received_mutex);
		bool complete = *first_received == count && *second_received == count;
		mutex_unlock(&received_mutex);
		if (complete) return;
		sleep_ms(5);
	}
	assert(!"ICE data did not traverse both directions");
}

static void shared_dual_stack(void) {
	uint16_t port4, port6, mux_port, peer_port;
	socket_t server4 = bound_socket(AF_INET, &port4), server6 = bound_socket(AF_INET6, &port6);
	socket_t reserved = bound_socket(AF_INET6, &mux_port);
	closesocket(reserved);
	reserved = bound_socket(AF_INET, &peer_port);
	closesocket(reserved);
	juice_config_t config = {0};
	config.concurrency_mode = JUICE_CONCURRENCY_MODE_MUX;
	config.local_port_range_begin = config.local_port_range_end = mux_port;
	config.stun_server_host = "127.0.0.1";
	config.stun_server_port = port4;
	unsigned int count4 = 0, count_peer = 0;
	config.cb_recv = received;
	config.user_ptr = &count4;
	juice_agent_t *monitor4 = juice_create(&config);
	config.stun_server_host = "::1";
	config.stun_server_port = port6;
	config.cb_recv = NULL;
	config.user_ptr = NULL;
	juice_agent_t *monitor6 = juice_create(&config);
	config.concurrency_mode = JUICE_CONCURRENCY_MODE_POLL;
	config.bind_address = "127.0.0.1";
	config.local_port_range_begin = config.local_port_range_end = peer_port;
	config.stun_server_host = NULL;
	config.stun_server_port = 0;
	config.cb_recv = received;
	config.user_ptr = &count_peer;
	juice_agent_t *peer = juice_create(&config);
	assert(monitor4 && monitor6 && peer);
	const char *password = "012345678901234567890123456789";
	assert(juice_set_local_ice_attributes(monitor4, "monitor", password) == 0);
	assert(juice_set_local_ice_attributes(peer, "peer", password) == 0);
	assert(juice_set_stun_monitoring(monitor4, true) == 0);
	assert(juice_set_stun_monitoring(monitor6, true) == 0);
	assert(juice_gather_candidates(monitor4) == 0);
	assert(juice_gather_candidates(monitor6) == 0);
	assert(juice_gather_candidates(peer) == 0);
	addr_record_t source4 = {0}, source6 = {0};
	stun_message_t message4 = request(server4, &source4, mux_port, 2000);
	stun_message_t message6 = request(server6, &source6, mux_port, 2000);
	respond(server4, &source4, &message4, AF_INET, 40000, 0);
	successes(monitor4, 1);
	assert(snapshot(monitor6).successful_responses == 0);
	char description[512];
	snprintf(description, sizeof(description),
	         "a=ice-ufrag:peer\r\na=ice-pwd:%s\r\na=candidate:1 1 UDP 123 127.0.0.1 %u typ host\r\na=end-of-candidates\r\n",
	         password, peer_port);
	assert(juice_set_remote_description(monitor4, description) == 0);
	snprintf(description, sizeof(description),
	         "a=ice-ufrag:monitor\r\na=ice-pwd:%s\r\na=candidate:1 1 UDP 123 127.0.0.1 %u typ host\r\na=end-of-candidates\r\n",
	         password, mux_port);
	assert(juice_set_remote_description(peer, description) == 0);
	for (int i = 0; i < 1000 && (juice_get_state(monitor4) != JUICE_STATE_COMPLETED ||
	                            juice_get_state(peer) != JUICE_STATE_COMPLETED); ++i) sleep_ms(5);
	assert(juice_get_state(monitor4) == JUICE_STATE_COMPLETED && juice_get_state(peer) == JUICE_STATE_COMPLETED);
	round_trip(monitor4, peer, &count4, &count_peer, 1);
	// Both families share the port but retain separate binding observations.
	respond(server6, &source6, &message6, AF_INET6, 40000, 0);
	juice_stun_binding_t binding6 = successes(monitor6, 1), binding4 = snapshot(monitor4);
	assert(binding4.successful_responses == 1 && binding4.mapping_revision == 1);
	assert(binding6.mapping_revision == 1);
	assert(strcmp(binding4.mapped_address, "198.51.100.10") == 0);
	assert(strcmp(binding6.mapped_address, "2001:db8::10") == 0);
	round_trip(monitor4, peer, &count4, &count_peer, 2);
	juice_destroy(monitor6);
	round_trip(monitor4, peer, &count4, &count_peer, 3);
	juice_destroy(peer);
	juice_destroy(monitor4);
	juice_mux_stats_t stats;
	assert(juice_mux_get_stats(NULL, mux_port, &stats) == JUICE_ERR_NOT_AVAIL);
	closesocket(server4);
	closesocket(server6);
	puts("STUN monitoring shared: dual-stack socket, nominated ICE data, independent observations and teardown PASS");
}

static void run_scenario(const char *scenario) {
	bool server_error = strcmp(scenario, "error") == 0;
	bool disabled = strcmp(scenario, "disabled") == 0;
	int family = strcmp(scenario, "6") == 0 ? AF_INET6 : AF_INET;
	const char *host = family == AF_INET ? "127.0.0.1" : "::1";
	uint16_t server_port, mux_port, wrong_port;
	socket_t server = bound_socket(family, &server_port);
	socket_t wrong_server = bound_socket(family, &wrong_port);
	socket_t reserved = bound_socket(family, &mux_port);
	closesocket(reserved);
	assert(juice_mux_listen_pending(host, mux_port, NULL, unexpected_peer, NULL) == 0);
	juice_config_t config = {0};
	config.concurrency_mode = JUICE_CONCURRENCY_MODE_MUX;
	config.bind_address = host;
	config.local_port_range_begin = config.local_port_range_end = mux_port;
	config.stun_server_host = host;
	config.stun_server_port = server_port;
	juice_agent_t *agent = juice_create(&config);
	assert(agent);
	juice_stun_binding_t binding;
	assert(juice_get_stun_binding(agent, 0, &binding) == JUICE_ERR_NOT_AVAIL);
	assert(juice_get_stun_binding(NULL, 0, &binding) == JUICE_ERR_INVALID);
	assert(juice_get_stun_binding(agent, 0, NULL) == JUICE_ERR_INVALID);
	assert(juice_set_stun_monitoring(NULL, true) == JUICE_ERR_INVALID);
	assert(juice_set_stun_monitoring(agent, !disabled) == 0);
	assert(juice_gather_candidates(agent) == 0);
	assert(juice_set_stun_monitoring(agent, false) == JUICE_ERR_FAILED);
	assert(juice_get_stun_binding(agent, 1, &binding) == JUICE_ERR_NOT_AVAIL);
	binding = snapshot(agent);
	assert(strcmp(binding.server_address, host) == 0 && binding.server_port == server_port);
	assert(!binding.mapped_address[0] && binding.last_success_age_ms == UINT64_MAX);
	addr_record_t source = {0};
	stun_message_t message = request(server, &source, mux_port, 2000);
	if (disabled || server_error) {
		respond(server, &source, &message, family, 0, 500);
		for (int i = 0; i < 400 && snapshot(agent).failed_transactions == 0; ++i) sleep_ms(5);
		binding = snapshot(agent);
		assert(binding.state == JUICE_STUN_BINDING_FAILED && binding.failed_transactions == 1);
		assert(binding.successful_responses == 0 && binding.last_success_age_ms == UINT64_MAX);
		assert(binding.mapping_revision == 0 && !binding.mapped_address[0]);
	} else {
		// Correct transaction IDs from the wrong server, malformed success, and
		// unknown transaction IDs must not refresh or publish an observation.
		respond(wrong_server, &source, &message, family, 40000, 0);
		respond(server, &source, &message, family, 0, 0);
		stun_message_t unknown = message;
		unknown.transaction_id[0] ^= 1;
		respond(server, &source, &unknown, family, 40000, 0);
		sleep_ms(100);
		assert(snapshot(agent).successful_responses == 0);
		respond(server, &source, &message, family, 40000, 0);
		binding = successes(agent, 1);
		assert(binding.mapping_revision == 1 && binding.mapped_port == 40000);
		assert(strcmp(binding.mapped_address, family == AF_INET ? "198.51.100.10" : "2001:db8::10") == 0);
		respond(server, &source, &message, family, 49999, 0);
		sleep_ms(100);
		binding = snapshot(agent);
		assert(binding.successful_responses == 1 && binding.mapping_revision == 1);
		assert(binding.mapped_port == 40000 && binding.last_success_age_ms >= 90);
	}
	juice_mux_stats_t stats;
	assert(juice_mux_get_stats(host, mux_port, &stats) == 0);
	assert(stats.agents == 1 && stats.mapped_tuples == 0 && stats.pending == 0 && stats.notifications == 0);
	assert(juice_get_state(agent) == JUICE_STATE_CONNECTING); // no ICE peer was invented
	juice_destroy(agent);
	assert(juice_mux_get_stats(host, mux_port, &stats) == 0 && stats.agents == 0);
	assert(juice_mux_listen_pending(host, mux_port, NULL, NULL, NULL) == 0);
	assert(juice_mux_get_stats(host, mux_port, &stats) == JUICE_ERR_NOT_AVAIL);
	closesocket(server);
	closesocket(wrong_server);
	printf("STUN monitoring %s: actual shared mux, zero peers, observations and teardown PASS\n", scenario);
}

int test_stun_monitoring(void) {
#ifdef _WIN32
	WSADATA data;
	if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
		return -1;
#endif
	juice_set_log_level(JUICE_LOG_LEVEL_FATAL);
	// Exercise observations without waiting for production keepalive or consent timers.
	run_scenario("4");
	run_scenario("6");
	run_scenario("error");
	run_scenario("disabled");
	shared_dual_stack();
	mutex_destroy(&received_mutex);
	juice_set_log_level(JUICE_LOG_LEVEL_WARN);
#ifdef _WIN32
	WSACleanup();
#endif
	return 0;
}
