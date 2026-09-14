/* SPDX-License-Identifier: MPL-2.0 */
#include <juice/juice.h>

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// A bounded executable for an external network-namespace lab. The server uses
// libjuice's actual STUN responder and reports the source seen by its UDP socket.
// No advertised mapping, packet tunnel, NAT policy or peer admission is invented here.
static uint64_t now_ms(void) {
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) abort();
	return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}

static int number(const char *value, int max) {
	if (!value[0]) return 0;
	for (const char *p = value; *p; ++p) if (*p < '0' || *p > '9') return 0;
	errno = 0;
	char *end;
	long parsed = strtol(value, &end, 10);
	return !errno && !*end && parsed > 0 && parsed <= max ? (int)parsed : 0;
}

static int numeric_family(const char *address) {
	struct in6_addr storage;
	if (!address) return 0;
	if (inet_pton(AF_INET, address, &storage) == 1) return AF_INET;
	if (inet_pton(AF_INET6, address, &storage) == 1) return AF_INET6;
	return 0;
}

static void reject_peer(const juice_mux_pending_request_t *request, void *ptr) {
	(void)request;
	(void)ptr;
	// A callback here is a probe failure; no application peer can be created.
	// Native pending attempts still have their bounded default deadline.
}

static int snapshot(juice_agent_t *agent, const char *address, uint16_t port, uint64_t elapsed) {
	juice_mux_stats_t stats;
	if (juice_mux_get_stats(address, port, &stats) != JUICE_ERR_SUCCESS) return -1;
	if (stats.agents != 1 || stats.mapped_tuples || stats.pending || stats.notifications) {
		fprintf(stderr, "Unexpected peer state on monitor mux\n");
		return -1;
	}
	juice_stun_binding_t binding;
	int result = juice_get_stun_binding(agent, 0, &binding);
	printf("{\"event\":\"snapshot\",\"elapsedMillis\":%" PRIu64
	       ",\"localPort\":%u,\"agents\":%d,\"mappedTuples\":%d,\"pending\":%u,\"notifications\":%" PRIu64,
	       elapsed, port, stats.agents, stats.mapped_tuples, stats.pending, stats.notifications);
	if (result == JUICE_ERR_NOT_AVAIL) {
		puts(",\"binding\":null}");
	} else if (result == JUICE_ERR_SUCCESS) {
		printf(",\"binding\":{\"serverAddress\":\"%s\",\"serverPort\":%u,"
		       "\"mappedAddress\":\"%s\",\"mappedPort\":%u,\"state\":%d,"
		       "\"successfulResponses\":%" PRIu64 ",\"failedTransactions\":%" PRIu64
		       ",\"mappingRevision\":%" PRIu64 ",\"lastSuccessAgeMillis\":",
		       binding.server_address, binding.server_port, binding.mapped_address, binding.mapped_port,
		       binding.state, binding.successful_responses, binding.failed_transactions, binding.mapping_revision);
		if (binding.last_success_age_ms == UINT64_MAX) printf("null");
		else printf("%" PRIu64, binding.last_success_age_ms);
		puts("}}");
	} else {
		puts(",\"error\":\"binding_unavailable\"}");
		return -1;
	}
	return fflush(stdout) == 0 ? 0 : -1;
}

int main(int argc, char **argv) {
	if (argc < 2 || (strcmp(argv[1], "server") && strcmp(argv[1], "monitor"))) return 2;
	const bool server_mode = strcmp(argv[1], "server") == 0;
	const char *bind_address = NULL, *stun_server = NULL;
	int local_port = 0, stun_port = 0, duration_ms = 0;
	for (int i = 2; i + 1 < argc; i += 2) {
		if (!strcmp(argv[i], "--bind-address") && !bind_address) bind_address = argv[i + 1];
		else if (!strcmp(argv[i], "--local-port") && !local_port) local_port = number(argv[i + 1], 65535);
		else if (!strcmp(argv[i], "--stun-server") && !stun_server) stun_server = argv[i + 1];
		else if (!strcmp(argv[i], "--stun-port") && !stun_port) stun_port = number(argv[i + 1], 65535);
		else if (!strcmp(argv[i], "--duration-ms") && !duration_ms) duration_ms = number(argv[i + 1], 3600000);
		else return 2;
	}
	if (argc % 2 || !numeric_family(bind_address) || !local_port || !duration_ms ||
	    (server_mode && (stun_server || stun_port)) ||
	    (!server_mode && (!stun_port || numeric_family(stun_server) != numeric_family(bind_address)))) {
		fprintf(stderr, "Explicit numeric bind/server addresses, ports and duration (1..3600000ms) required\n");
		return 2;
	}
	juice_set_log_level(JUICE_LOG_LEVEL_FATAL);
	uint64_t start = now_ms();
	if (server_mode) {
		juice_server_config_t config = {0};
		config.bind_address = bind_address;
		config.port = (uint16_t)local_port;
		juice_server_t *server = juice_server_create(&config);
		if (!server || juice_server_get_port(server) != local_port) {
			if (server) juice_server_destroy(server);
			fprintf(stderr, "Failed to bind controlled STUN responder\n");
			return 1;
		}
		printf("{\"event\":\"ready\",\"role\":\"server\",\"address\":\"%s\",\"port\":%d}\n", bind_address, local_port);
		fflush(stdout);
		while (now_ms() - start < (uint64_t)duration_ms) usleep(100000);
		juice_server_destroy(server);
		puts("{\"event\":\"closed\",\"role\":\"server\"}");
		return 0;
	}
	if (juice_mux_listen_pending(bind_address, (uint16_t)local_port, NULL, reject_peer, NULL) != JUICE_ERR_SUCCESS) return 1;
	juice_config_t config = {0};
	config.concurrency_mode = JUICE_CONCURRENCY_MODE_MUX;
	config.bind_address = bind_address;
	config.local_port_range_begin = config.local_port_range_end = (uint16_t)local_port;
	config.stun_server_host = stun_server;
	config.stun_server_port = (uint16_t)stun_port;
	juice_agent_t *agent = juice_create(&config);
	int result = 1;
	if (!agent || juice_set_stun_monitoring(agent, true) != JUICE_ERR_SUCCESS ||
	    juice_gather_candidates(agent) != JUICE_ERR_SUCCESS) goto cleanup;
	printf("{\"event\":\"ready\",\"role\":\"monitor\",\"address\":\"%s\",\"port\":%d}\n", bind_address, local_port);
	fflush(stdout);
	uint64_t next = 0;
	while (now_ms() - start < (uint64_t)duration_ms) {
		uint64_t elapsed = now_ms() - start;
		if (elapsed >= next) {
			if (snapshot(agent, bind_address, (uint16_t)local_port, elapsed) != 0) goto cleanup;
			next = elapsed + 1000;
		}
		usleep(100000);
	}
	result = snapshot(agent, bind_address, (uint16_t)local_port, now_ms() - start) == 0 ? 0 : 1;
cleanup:
	if (agent) juice_destroy(agent);
	juice_mux_stats_t stats;
	if (juice_mux_get_stats(bind_address, (uint16_t)local_port, &stats) != JUICE_ERR_SUCCESS || stats.agents != 0) result = 1;
	if (juice_mux_listen_pending(bind_address, (uint16_t)local_port, NULL, NULL, NULL) != JUICE_ERR_SUCCESS) result = 1;
	if (juice_mux_get_stats(bind_address, (uint16_t)local_port, &stats) != JUICE_ERR_NOT_AVAIL) result = 1;
	printf("{\"event\":\"closed\",\"role\":\"monitor\",\"socketReleased\":%s}\n", result ? "false" : "true");
	return result;
}
