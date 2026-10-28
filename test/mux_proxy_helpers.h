/* SPDX-License-Identifier: MPL-2.0 */
#ifndef JUICE_MUX_PROXY_HELPERS_H
#define JUICE_MUX_PROXY_HELPERS_H
#include "mux_test_helpers.h"

#define CLIENT "203.0.113.7"

// A relay's header for a datagram from the given client, IPv6 if it has a colon
static size_t proxy_header(unsigned char *out, const char *client, uint16_t client_port,
                           uint16_t port) {
	static const unsigned char signature[12] = {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D,
	                                            0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A};
	bool v6 = strchr(client, ':') != NULL;
	int family = v6 ? AF_INET6 : AF_INET;
	size_t length = v6 ? 16 : 4;
	memcpy(out, signature, sizeof(signature));
	out[12] = 0x21;            // v2, PROXY
	out[13] = v6 ? 0x22 : 0x12; // datagram
	out[14] = 0;
	out[15] = (unsigned char)(2 * length + 4);
	assert(inet_pton(family, client, out + 16) == 1);
	assert(inet_pton(family, v6 ? "::1" : "127.0.0.1", out + 16 + length) == 1);
	unsigned char *ports = out + 16 + 2 * length;
	ports[0] = client_port >> 8;
	ports[1] = client_port & 0xFF;
	ports[2] = port >> 8;
	ports[3] = port & 0xFF;
	return 16 + 2 * length + 4;
}

// A payload behind a header declaring client and client_port, or bare if client is NULL
static void send_relayed(int fd, uint16_t port, const char *client, uint16_t client_port,
                         const void *payload, size_t payload_size) {
	unsigned char datagram[2048];
	size_t offset = client ? proxy_header(datagram, client, client_port, port) : 0;
	assert(offset + payload_size <= sizeof(datagram));
	memcpy(datagram + offset, payload, payload_size);
	struct sockaddr_in destination = {.sin_family = AF_INET, .sin_port = htons(port)};
	assert(inet_pton(AF_INET, "127.0.0.1", &destination.sin_addr) == 1);
	ssize_t size = (ssize_t)(offset + payload_size);
	struct sockaddr *to = (struct sockaddr *)&destination;
	assert(sendto(fd, datagram, size, 0, to, sizeof(destination)) == size);
}

// A binding request signed with password, behind a header unless client is NULL
static void send_signed(int fd, uint16_t port, const char *client, uint16_t client_port,
                        const char *password) {
	stun_message_t request = {0};
	request.msg_class = STUN_CLASS_REQUEST;
	request.msg_method = STUN_METHOD_BINDING;
	request.priority = 123456;
	request.ice_controlling = 123456789;
	memcpy(request.transaction_id, "firstrequest", STUN_TRANSACTION_ID_SIZE);
	snprintf(request.credentials.username, sizeof(request.credentials.username), "host:peer");
	unsigned char message[1024];
	int size = _juice_stun_write(message, sizeof(message), &request, password);
	assert(size > 0);
	send_relayed(fd, port, client, client_port, message, (size_t)size);
}

// Asserts the relay port that routes CLIENT on client_port, none if relay is 0
static void assert_relay(uint16_t port, uint16_t client_port, uint16_t relay) {
	char found[64], expected[64];
	int result =
	    juice_mux_get_proxy_relay("127.0.0.1", port, CLIENT, client_port, found, sizeof(found));
	if (!relay) {
		assert(result == JUICE_ERR_NOT_AVAIL);
		return;
	}
	snprintf(expected, sizeof(expected), "127.0.0.1:%u", relay);
	assert(result == 0 && strcmp(found, expected) == 0);
}
#endif
