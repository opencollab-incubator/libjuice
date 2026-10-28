/* SPDX-License-Identifier: MPL-2.0 */
#include "mux_proxy.h"
#include "juice.h"
#include "log.h"
#include "socket.h"
#include "stun.h"
#include "thread.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_RANGES 4096
#define FLOW_BUCKET_BITS 14
#define FLOW_BUCKETS (1 << FLOW_BUCKET_BITS)
#ifndef MAX_FLOWS // a test may lower it
#define MAX_FLOWS FLOW_BUCKETS // at most one flow per bucket on average
#endif
#define MAX_CLAIMS 4096
#define FIBONACCI 0x9E3779B97F4A7C15ull // 2^64 divided by the golden ratio
#define FLOW_TIMEOUT 120000 // ms, well past ICE consent checks
#define CLAIM_TIMEOUT 30000 // ms, past any connectivity check of the claimed client
#define FULL_RECHECK 1000 // ms before a full table of live clients is looked through again
#define HEADER_ABSENT -1
#define HEADER_INVALID -2

static const char signature[12] = {'\r', '\n', '\r', '\n', '\0', '\r',
                                   '\n', 'Q',  'U',  'I',  'T',  '\n'};

enum { RELAY, CLIENT };

typedef struct proxy_range {
	int family;
	unsigned char address[16];
	int prefix;
} proxy_range_t;

// A routed flow takes the client's replies to its relay. A claimed one only attributes the relay's
// datagrams to the client its header declared, until one of them authenticates.
typedef enum flow_state { FLOW_ROUTED, FLOW_CLAIMED } flow_state_t;

// One client behind a relay, which the relay reaches from its own source port. Indexed by both,
// except a claimed flow by its relay only.
typedef struct proxy_flow {
	addr_record_t addr[2];
	struct proxy_flow *next[2];
	struct proxy_flow *older, *newer;
	timestamp_t last_seen;
	flow_state_t state;
	// Another client the relay's latest header declared, which speaks once the routed one is gone
	addr_record_t successor;
	bool has_successor;
} proxy_flow_t;

typedef struct flow_ages {
	proxy_flow_t *oldest, *newest;
	size_t count;
} flow_ages_t;

struct mux_proxy {
	mutex_t *lock;
	mux_proxy_alive_t alive;
	void *alive_ptr;
	proxy_range_t *ranges;
	size_t range_count;
	proxy_flow_t *buckets[2][FLOW_BUCKETS];
	// Apart, so claims never take the room or the place of a route
	flow_ages_t routes, claims;
	timestamp_t full_until;
};

static int parse_range(const char *entry, proxy_range_t *range) {
	char host[ADDR_MAX_NUMERICHOST_LEN];
	const char *slash = strchr(entry, '/');
	size_t length = slash ? (size_t)(slash - entry) : strlen(entry);
	if (length == 0 || length >= sizeof(host))
		return -1;
	memcpy(host, entry, length);
	host[length] = '\0';

	if (inet_pton(AF_INET, host, range->address) == 1)
		range->family = AF_INET;
	else if (inet_pton(AF_INET6, host, range->address) == 1)
		range->family = AF_INET6;
	else
		return -1;

	int bits = range->family == AF_INET ? 32 : 128;
	range->prefix = bits;
	if (slash) {
		char *end;
		long prefix = strtol(slash + 1, &end, 10);
		if (end == slash + 1 || *end != '\0' || prefix < 0 || prefix > bits)
			return -1;
		range->prefix = (int)prefix;
	}
	return 0;
}

static bool range_contains(const proxy_range_t *range, const addr_record_t *record) {
	const unsigned char *address;
	const struct sockaddr *sa = (const struct sockaddr *)&record->addr;
	if (sa->sa_family != range->family)
		return false;
	if (sa->sa_family == AF_INET)
		address = (const unsigned char *)&((const struct sockaddr_in *)sa)->sin_addr;
	else
		address = (const unsigned char *)&((const struct sockaddr_in6 *)sa)->sin6_addr;

	int full = range->prefix / 8, rest = range->prefix % 8;
	if (memcmp(address, range->address, full) != 0)
		return false;
	if (rest == 0)
		return true;
	unsigned char mask = (unsigned char)(0xFF << (8 - rest));
	return (address[full] & mask) == (range->address[full] & mask);
}

static bool is_relay(const mux_proxy_t *proxy, const addr_record_t *src) {
	for (size_t i = 0; i < proxy->range_count; ++i)
		if (range_contains(proxy->ranges + i, src))
			return true;
	return false;
}

static bool is_stun_response(const char *data, size_t size) {
	return is_stun_datagram(data, size) &&
	       STUN_IS_RESPONSE(ntohs(((const struct stun_header *)data)->type) & STUN_CLASS_MASK);
}

// Returns the header length and the declared client, or HEADER_ABSENT or HEADER_INVALID
static int read_header(const char *data, size_t size, addr_record_t *client) {
	if (size < 16 || memcmp(data, signature, sizeof(signature)) != 0)
		return HEADER_ABSENT;

	const unsigned char *header = (const unsigned char *)data;
	size_t total = 16 + ((size_t)header[14] << 8 | header[15]);
	// A LOCAL command, such as a health check, declares no client
	if (total > size || header[12] != 0x21)
		return HEADER_INVALID;

	memset(client, 0, sizeof(*client));
	client->socktype = SOCK_DGRAM;
	if (header[13] == 0x12 && total >= 16 + 12) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&client->addr;
		sin->sin_family = AF_INET;
		memcpy(&sin->sin_addr, header + 16, 4);
		memcpy(&sin->sin_port, header + 24, 2);
		client->len = sizeof(*sin);
	} else if (header[13] == 0x22 && total >= 16 + 36) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&client->addr;
		sin6->sin6_family = AF_INET6;
		memcpy(&sin6->sin6_addr, header + 16, 16);
		memcpy(&sin6->sin6_port, header + 48, 2);
		client->len = sizeof(*sin6);
		// As every receive path does, so a dual-stack relay's IPv4 clients stay IPv4
		addr_unmap_inet6_v4mapped((struct sockaddr *)&client->addr, &client->len);
	} else {
		return HEADER_INVALID;
	}
	return (int)total;
}

// The address and port packed into one key and mixed by a multiply. libjuice's djb2 address hash
// collides on sequential ports and addresses, which relays and clients often are.
static proxy_flow_t **bucket(mux_proxy_t *proxy, int key, const addr_record_t *addr) {
	const struct sockaddr *sa = (const struct sockaddr *)&addr->addr;
	uint64_t packed;
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
		packed = (uint64_t)sin->sin_addr.s_addr << 16 | sin->sin_port;
	} else {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
		uint64_t words[2];
		memcpy(words, &sin6->sin6_addr, sizeof(words));
		packed = (words[0] * FIBONACCI ^ words[1]) + sin6->sin6_port;
	}
	return &proxy->buckets[key][(packed * FIBONACCI) >> (64 - FLOW_BUCKET_BITS)];
}

static bool indexed(const proxy_flow_t *flow, int key) {
	return key == RELAY || flow->state == FLOW_ROUTED;
}

static flow_ages_t *ages_of(mux_proxy_t *proxy, const proxy_flow_t *flow) {
	return flow->state == FLOW_CLAIMED ? &proxy->claims : &proxy->routes;
}

static proxy_flow_t *find_flow(mux_proxy_t *proxy, int key, const addr_record_t *addr) {
	for (proxy_flow_t *flow = *bucket(proxy, key, addr); flow; flow = flow->next[key])
		if (addr_record_is_equal(&flow->addr[key], addr, true))
			return flow;
	return NULL;
}

static void append_age(flow_ages_t *ages, proxy_flow_t *flow) {
	flow->older = ages->newest;
	flow->newer = NULL;
	if (ages->newest)
		ages->newest->newer = flow;
	else
		ages->oldest = flow;
	ages->newest = flow;
}

static void unlink_age(flow_ages_t *ages, proxy_flow_t *flow) {
	if (flow->older)
		flow->older->newer = flow->newer;
	else
		ages->oldest = flow->newer;
	if (flow->newer)
		flow->newer->older = flow->older;
	else
		ages->newest = flow->older;
}

// Sends only read the client chains, so the age lists need no lock
static void touch_flow(mux_proxy_t *proxy, proxy_flow_t *flow, timestamp_t now) {
	flow_ages_t *ages = ages_of(proxy, flow);
	flow->last_seen = now;
	if (flow != ages->newest) {
		unlink_age(ages, flow);
		append_age(ages, flow);
	}
}

static void unlink_key(mux_proxy_t *proxy, proxy_flow_t *flow, int key) {
	proxy_flow_t **link = bucket(proxy, key, &flow->addr[key]);
	while (*link != flow)
		link = &(*link)->next[key];
	*link = flow->next[key];
}

// The caller holds the lock for a flow indexed by client, unless no send can reach it anymore
static void remove_flow(mux_proxy_t *proxy, proxy_flow_t *flow) {
	for (int key = RELAY; key <= CLIENT; ++key)
		if (indexed(flow, key))
			unlink_key(proxy, flow, key);
	flow_ages_t *ages = ages_of(proxy, flow);
	unlink_age(ages, flow);
	--ages->count;
	free(flow);
}

static bool expired(const flow_ages_t *ages, timestamp_t now, timediff_t timeout) {
	return ages->oldest && ages->oldest->last_seen + timeout < now;
}

static proxy_flow_t *new_flow(const addr_record_t *relay, const addr_record_t *client,
                              timestamp_t last_seen, flow_state_t state) {
	proxy_flow_t *flow = calloc(1, sizeof(*flow));
	if (!flow) {
		JLOG_ERROR("Memory allocation failed for proxy flow");
		return NULL;
	}
	flow->addr[RELAY] = *relay;
	flow->addr[CLIENT] = *client;
	flow->last_seen = last_seen;
	flow->state = state;
	return flow;
}

// As the newest flow. The caller holds the lock for a flow indexed by client, unless no send can
// reach the proxy yet.
static void insert_flow(mux_proxy_t *proxy, proxy_flow_t *flow) {
	for (int key = RELAY; key <= CLIENT; ++key) {
		if (!indexed(flow, key))
			continue;
		proxy_flow_t **head = bucket(proxy, key, &flow->addr[key]);
		flow->next[key] = *head;
		*head = flow;
	}
	flow_ages_t *ages = ages_of(proxy, flow);
	append_age(ages, flow);
	++ages->count;
}

static int copy_flow(mux_proxy_t *proxy, const proxy_flow_t *flow) {
	proxy_flow_t *copy =
	    new_flow(&flow->addr[RELAY], &flow->addr[CLIENT], flow->last_seen, flow->state);
	if (!copy)
		return -1;
	copy->successor = flow->successor;
	copy->has_successor = flow->has_successor;
	insert_flow(proxy, copy);
	return 0;
}

// Attributes the relay's datagrams to the client until one authenticates, as a relay may prefix
// only the first datagram of a flow
static proxy_flow_t *claim(mux_proxy_t *proxy, const addr_record_t *relay,
                           const addr_record_t *client, timestamp_t now) {
	if (proxy->claims.count >= MAX_CLAIMS)
		remove_flow(proxy, proxy->claims.oldest);
	proxy_flow_t *flow = new_flow(relay, client, now, FLOW_CLAIMED);
	if (flow)
		insert_flow(proxy, flow);
	return flow;
}

int mux_proxy_create(const char *const *relays, size_t count, mutex_t *lock,
                     mux_proxy_alive_t alive, void *alive_ptr, const mux_proxy_t *previous,
                     mux_proxy_t **proxy) {
	if (count > MAX_RANGES)
		return JUICE_ERR_INVALID;
	mux_proxy_t *created = calloc(1, sizeof(*created));
	proxy_range_t *ranges = calloc(count, sizeof(*ranges));
	if (!created || !ranges) {
		free(created);
		free(ranges);
		return JUICE_ERR_FAILED;
	}
	for (size_t i = 0; i < count; ++i) {
		if (!relays[i] || parse_range(relays[i], ranges + i) != 0) {
			JLOG_ERROR("Invalid PROXY protocol relay: %s", relays[i] ? relays[i] : "(null)");
			free(created);
			free(ranges);
			return JUICE_ERR_INVALID;
		}
	}
	created->lock = lock;
	created->alive = alive;
	created->alive_ptr = alive_ptr;
	created->ranges = ranges;
	created->range_count = count;
	// Oldest first, so the age order carries over. Sends may still read previous, never write it.
	if (previous) {
		const flow_ages_t *lists[] = {&previous->routes, &previous->claims};
		for (int i = 0; i < 2; ++i)
			for (const proxy_flow_t *flow = lists[i]->oldest; flow; flow = flow->newer)
				if (is_relay(created, &flow->addr[RELAY]) && copy_flow(created, flow) != 0)
					goto error;
	}
	*proxy = created;
	return 0;

error:
	mux_proxy_destroy(created);
	return JUICE_ERR_FAILED;
}

void mux_proxy_destroy(mux_proxy_t *proxy) {
	if (!proxy)
		return;
	while (proxy->routes.oldest)
		remove_flow(proxy, proxy->routes.oldest);
	while (proxy->claims.oldest)
		remove_flow(proxy, proxy->claims.oldest);
	free(proxy->ranges);
	free(proxy);
}

int mux_proxy_receive(mux_proxy_t *proxy, char **data, size_t *size, addr_record_t *src,
                      addr_record_t *relay, timestamp_t now) {
	if (expired(&proxy->routes, now, FLOW_TIMEOUT)) {
		mutex_lock(proxy->lock);
		while (expired(&proxy->routes, now, FLOW_TIMEOUT))
			remove_flow(proxy, proxy->routes.oldest);
		mutex_unlock(proxy->lock);
	}
	while (expired(&proxy->claims, now, CLAIM_TIMEOUT))
		remove_flow(proxy, proxy->claims.oldest);

	addr_record_t client;
	int header = read_header(*data, *size, &client);
	if (header == HEADER_INVALID)
		return -1;
	proxy_flow_t *flow = find_flow(proxy, RELAY, src);
	if (header == HEADER_ABSENT) {
		// Some relays only prefix the first datagram of a flow
		if (!flow)
			// Behind relays no peer comes straight here. A STUN response stays, as it only
			// matches a request this endpoint sent, such as one to a STUN server.
			return is_stun_response(*data, *size) ? 0 : -1;
	} else {
		// A header from anywhere else is spoofed. A flow implies a listed relay, since a new list
		// keeps only the flows of relays it lists.
		if (!flow && !is_relay(proxy, src))
			return -1;
		*data += header;
		*size -= (size_t)header;
		if (*size == 0)
			return -1;
		if (flow && flow->state == FLOW_ROUTED) {
			// Remembered for once the routed client is gone, as a relay prefixing only the first
			// datagram of a flow will not declare it again
			flow->has_successor = !addr_record_is_equal(&flow->addr[CLIENT], &client, true);
			flow->successor = client;
			if (flow->has_successor) {
				// The routed client keeps the relay while it lives, see mux_proxy_admits
				*relay = *src;
				*src = client;
				return 1;
			}
		} else if (flow) {
			flow->addr[CLIENT] = client; // a claim is not indexed by client
		} else if (!(flow = claim(proxy, src, &client, now))) {
			return -1;
		}
	}
	touch_flow(proxy, flow, now);
	bool vacated = flow->state == FLOW_ROUTED && flow->has_successor &&
	               !proxy->alive(&flow->addr[CLIENT], proxy->alive_ptr);
	if (flow->state == FLOW_CLAIMED || vacated) {
		*relay = *src;
		*src = vacated ? flow->successor : flow->addr[CLIENT];
		return 1;
	}
	*src = flow->addr[CLIENT];
	return 0;
}

// The oldest route of a client that is gone. Refreshing keeps such routes, as a relay prefixing
// only the first datagram of a flow names a successor once, so a full table alone gives them up.
static proxy_flow_t *dead_route(mux_proxy_t *proxy) {
	timestamp_t now = current_timestamp();
	if (now < proxy->full_until)
		return NULL;
	for (proxy_flow_t *flow = proxy->routes.oldest; flow; flow = flow->newer)
		if (!proxy->alive(&flow->addr[CLIENT], proxy->alive_ptr))
			return flow;
	// So a flood of joins does not look through every route each
	proxy->full_until = now + FULL_RECHECK;
	return NULL;
}

// evicted is the route that makes room, if one has to
static bool admits(mux_proxy_t *proxy, const addr_record_t *relay, const addr_record_t *client,
                   proxy_flow_t **evicted) {
	*evicted = NULL;
	if (!is_relay(proxy, relay))
		return false;
	// A relay's port passes to another client only once the agent of the one it routes is gone.
	// ICE consent keeps an agent alive, which takes the client's own credentials.
	proxy_flow_t *held = find_flow(proxy, RELAY, relay);
	bool routed = held && held->state == FLOW_ROUTED;
	if (routed && !addr_record_is_equal(&held->addr[CLIENT], client, true) &&
	    proxy->alive(&held->addr[CLIENT], proxy->alive_ptr))
		return false;
	// Taking the relay's route or moving the client's own leaves the table no fuller
	if (routed || find_flow(proxy, CLIENT, client) || proxy->routes.count < MAX_FLOWS)
		return true;
	return (*evicted = dead_route(proxy)) != NULL;
}

bool mux_proxy_admits(mux_proxy_t *proxy, const addr_record_t *relay, const addr_record_t *client) {
	proxy_flow_t *evicted;
	return admits(proxy, relay, client, &evicted);
}

int mux_proxy_commit(mux_proxy_t *proxy, const addr_record_t *relay, const addr_record_t *client,
                     timestamp_t now) {
	proxy_flow_t *evicted;
	if (!admits(proxy, relay, client, &evicted))
		return -1;
	proxy_flow_t *held = find_flow(proxy, RELAY, relay);
	proxy_flow_t *own = find_flow(proxy, CLIENT, client);
	if (held && held == own) {
		touch_flow(proxy, held, now);
		return 0;
	}
	proxy_flow_t *flow = new_flow(relay, client, now, FLOW_ROUTED);
	if (!flow)
		return -1;

	mutex_lock(proxy->lock);
	if (held)
		remove_flow(proxy, held);
	// A client has one relay, so it moves
	if (own)
		remove_flow(proxy, own);
	if (evicted)
		remove_flow(proxy, evicted);
	insert_flow(proxy, flow);
	mutex_unlock(proxy->lock);
	return 0;
}

const addr_record_t *mux_proxy_relay(mux_proxy_t *proxy, const addr_record_t *client) {
	proxy_flow_t *flow = find_flow(proxy, CLIENT, client);
	return flow ? &flow->addr[RELAY] : NULL;
}

// A STUN server lookup, which carries no credentials, unlike an ICE check
static bool is_stun_lookup(const char *data, size_t size) {
	stun_message_t msg;
	return is_stun_datagram(data, size) && stun_read((void *)data, size, &msg) >= 0 &&
	       msg.msg_class == STUN_CLASS_REQUEST && msg.msg_method == STUN_METHOD_BINDING &&
	       !msg.has_integrity && *msg.credentials.username == '\0';
}

const addr_record_t *mux_proxy_route(mux_proxy_t *proxy, const addr_record_t *dst,
                                     const char *data, size_t size) {
	const addr_record_t *relay = mux_proxy_relay(proxy, dst);
	if (relay)
		return relay;
	return is_stun_lookup(data, size) ? dst : NULL;
}
