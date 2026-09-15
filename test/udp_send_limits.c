/* SPDX-License-Identifier: MPL-2.0 */
#include <juice/juice.h>
#include "agent.h"
#include "conn.h"
#include "stun.h"
#include <arpa/inet.h>
#include <assert.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int receiver(int family, addr_record_t *address) {
    memset(address, 0, sizeof(*address)); address->socktype = SOCK_DGRAM;
    if (family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)&address->addr;
        a->sin_family = family; a->sin_addr.s_addr = htonl(INADDR_LOOPBACK); address->len = sizeof(*a);
    } else {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&address->addr;
        a->sin6_family = family; a->sin6_addr = in6addr_loopback; address->len = sizeof(*a);
    }
    int fd = socket(family, SOCK_DGRAM, 0); assert(fd >= 0);
    assert(bind(fd, (struct sockaddr *)&address->addr, address->len) == 0);
    assert(getsockname(fd, (struct sockaddr *)&address->addr, &address->len) == 0);
    return fd;
}
static uint16_t free_port(int family) { addr_record_t a; int fd = receiver(family, &a); close(fd); return addr_get_port((struct sockaddr *)&a.addr); }
static juice_agent_t *agent(const char *host, uint16_t port, const juice_udp_send_limits_t *limits, uint16_t stun_port) {
    juice_config_t c = {0}; c.concurrency_mode = JUICE_CONCURRENCY_MODE_MUX;
    c.bind_address = host; c.local_port_range_begin = c.local_port_range_end = port;
    if (stun_port) { c.stun_server_host = host; c.stun_server_port = stun_port; }
    juice_agent_t *a = juice_create(&c); assert(a);
    if (limits) assert(juice_set_udp_send_limits(a, limits) == JUICE_ERR_SUCCESS);
    assert(juice_gather_candidates(a) == 0); return a;
}
static juice_udp_send_stats_t stats(juice_agent_t *a) { juice_udp_send_stats_t s; assert(juice_get_udp_send_stats(a, &s) == 0); return s; }
static ssize_t packet(int fd, unsigned char *bytes, size_t size, int timeout) {
    struct pollfd pollfd = {fd, POLLIN, 0};
    if (poll(&pollfd, 1, timeout) == 0) return -1;
    return recv(fd, bytes, size, 0);
}
struct sender { juice_agent_t *agent; addr_record_t destination; };
static void *concurrent_send(void *opaque) {
    struct sender *s = opaque;
    for (int i = 0; i < 100; ++i) conn_send(s->agent, &s->destination, "test", 4, 0);
    return NULL;
}
static void limits_case(int family) {
    const char *host = family == AF_INET ? "127.0.0.1" : "::1";
    addr_record_t dst; int fd = receiver(family, &dst); uint16_t port = free_port(family);
    juice_udp_send_limits_t limits = {32, 1200, juice_monotonic_time_ms() + 10000, host, addr_get_port((struct sockaddr *)&dst.addr)};
    juice_agent_t *limited = agent(host, port, &limits, 0), *ordinary = agent(host, port, NULL, 0);
    assert(juice_get_udp_send_stats(ordinary, &(juice_udp_send_stats_t){0}) == JUICE_ERR_NOT_AVAIL);
    assert(juice_set_udp_send_limits(limited, &limits) == JUICE_ERR_INVALID);
    unsigned char bytes[1400] = {0};
    assert(conn_send(limited, &dst, (char *)bytes, 1201, 0) < 0);
    assert(stats(limited).last_rejection == JUICE_UDP_SEND_SIZE);
    addr_record_t wrong = dst; addr_set_port((struct sockaddr *)&wrong.addr, (uint16_t)(limits.destination_port == 65535 ? 65534 : limits.destination_port + 1));
    assert(conn_send(limited, &wrong, "x", 1, 0) < 0);
    assert(stats(limited).last_rejection == JUICE_UDP_SEND_DESTINATION);
    assert(conn_send(limited, &dst, (char *)bytes, 1200, 0) == 1200);
    assert(packet(fd, bytes, sizeof(bytes), 500) == 1200);
    struct sender input = {limited, dst}; pthread_t threads[4];
    for (int i = 0; i < 4; ++i) assert(pthread_create(&threads[i], NULL, concurrent_send, &input) == 0);
    for (int i = 0; i < 4; ++i) assert(pthread_join(threads[i], NULL) == 0);
    for (int i = 0; i < 31; ++i) assert(packet(fd, bytes, sizeof(bytes), 500) == 4);
    assert(packet(fd, bytes, sizeof(bytes), 50) == -1);
    juice_udp_send_stats_t s = stats(limited);
    assert(s.reserved_datagrams == 32 && s.sent_datagrams == 32 && s.sent_bytes == 1200 + 31 * 4);
    assert(s.rejected_datagrams == 371 && s.last_rejection == JUICE_UDP_SEND_COUNT);
    // Same physical UDP mux, distinct agent: exhausted diagnostic budget cannot limit an ordinary peer.
    assert(conn_send(ordinary, &dst, (char *)bytes, 1201, 0) == 1201);
    assert(packet(fd, bytes, sizeof(bytes), 500) == 1201);
    juice_destroy(limited); juice_destroy(ordinary);
    limits.deadline_monotonic_ms = juice_monotonic_time_ms() + 30;
    limited = agent(host, port, &limits, 0); usleep(50000);
    assert(conn_send(limited, &dst, "x", 1, 0) < 0);
    s = stats(limited); assert(s.reserved_datagrams == 0 && s.last_rejection == JUICE_UDP_SEND_EXPIRED);
    assert(packet(fd, bytes, sizeof(bytes), 50) == -1);
    juice_destroy(limited);
    limits.deadline_monotonic_ms = juice_monotonic_time_ms() + 10000; limits.max_datagrams = 1;
    limited = agent(host, port, &limits, 0);
    // Real sendto EFAULT: failed OS attempts cannot refund a fixed peer budget.
    assert(conn_send(limited, &dst, NULL, 1, 0) < 0);
    s = stats(limited); assert(s.reserved_datagrams == 1 && s.sent_datagrams == 0);
    assert(conn_send(limited, &dst, "x", 1, 0) < 0);
    assert(stats(limited).last_rejection == JUICE_UDP_SEND_COUNT);
    assert(packet(fd, bytes, sizeof(bytes), 50) == -1);
    juice_destroy(limited); close(fd);
    printf("udp limits IPv%d: concurrent32, payload1200, destination, fixed expiry, shared unlimited agent PASS\n", family == AF_INET ? 4 : 6);
}
static void stun_case(int family) {
    const char *host = family == AF_INET ? "127.0.0.1" : "::1";
    addr_record_t dst; int fd = receiver(family, &dst);
    juice_udp_send_limits_t limits = {2, 1200, juice_monotonic_time_ms() + 10000, host, addr_get_port((struct sockaddr *)&dst.addr)};
    juice_agent_t *a = agent(host, free_port(family), &limits, limits.destination_port);
    unsigned char data[1400];
    for (int i = 0; i < 2; ++i) {
        ssize_t size = packet(fd, data, sizeof(data), 3000); assert(size > 0 && size <= 1200);
        stun_message_t request = {0}; assert(_juice_stun_read(data, (size_t)size, &request) > 0);
        assert(request.msg_class == STUN_CLASS_REQUEST && request.msg_method == STUN_METHOD_BINDING);
    }
    for (int i = 0; i < 300 && !stats(a).rejected_datagrams; ++i) usleep(10000);
    juice_udp_send_stats_t s = stats(a);
    assert(s.reserved_datagrams == 2 && s.sent_datagrams == 2 && s.last_rejection == JUICE_UDP_SEND_COUNT);
    assert(packet(fd, data, sizeof(data), 50) == -1);
    juice_destroy(a); close(fd);
    printf("udp limits IPv%d: real STUN retransmissions stopped at2 PASS\n", family == AF_INET ? 4 : 6);
}
static void invalid_case(void) {
    juice_config_t c = {0}; c.concurrency_mode = JUICE_CONCURRENCY_MODE_MUX;
    juice_agent_t *a = juice_create(&c); assert(a);
    juice_udp_send_limits_t good = {256, 1200, juice_monotonic_time_ms() + 10000, NULL, 0}, bad;
    const char *invalid_hosts[] = {"localhost", "::ffff:127.0.0.1", "::", "0.0.0.0", "fe80::1%eth0"};
    for (unsigned i = 0; i < sizeof(invalid_hosts) / sizeof(*invalid_hosts); ++i) { bad = good; bad.destination_address = invalid_hosts[i]; bad.destination_port = 1000; assert(juice_set_udp_send_limits(a, &bad) == JUICE_ERR_INVALID); }
    bad = good; bad.max_datagrams = 0; assert(juice_set_udp_send_limits(a, &bad) == JUICE_ERR_INVALID);
    bad = good; bad.max_payload_bytes = 65508; assert(juice_set_udp_send_limits(a, &bad) == JUICE_ERR_INVALID);
    bad = good; bad.deadline_monotonic_ms = UINT64_MAX; assert(juice_set_udp_send_limits(a, &bad) == JUICE_ERR_INVALID);
    bad = good; bad.deadline_monotonic_ms = juice_monotonic_time_ms(); assert(juice_set_udp_send_limits(a, &bad) == JUICE_ERR_INVALID);
    assert(juice_set_udp_send_limits(a, &good) == 0);
    assert(juice_set_udp_send_limits(a, &good) == JUICE_ERR_INVALID);
    assert(juice_set_ice_tcp_mode(a, JUICE_ICE_TCP_MODE_ACTIVE) == JUICE_ERR_INVALID);
    assert(juice_add_turn_server(a, &(juice_turn_server_t){.host = "127.0.0.1", .port = 3478}) != 0);
    juice_destroy(a);
    c.concurrency_mode = JUICE_CONCURRENCY_MODE_POLL; a = juice_create(&c);
    assert(juice_set_udp_send_limits(a, &good) == JUICE_ERR_INVALID); juice_destroy(a);
    puts("udp limits invalid/unsupported/immutable configuration PASS");
}
int main(int argc, char **argv) {
    juice_set_log_level(JUICE_LOG_LEVEL_NONE);
    assert(argc == 2);
    if (!strcmp(argv[1], "invalid")) invalid_case();
    else if (!strcmp(argv[1], "4")) limits_case(AF_INET);
    else if (!strcmp(argv[1], "6")) limits_case(AF_INET6);
    else if (!strcmp(argv[1], "stun4")) stun_case(AF_INET);
    else if (!strcmp(argv[1], "stun6")) stun_case(AF_INET6);
    else assert(0);
    return 0;
}
