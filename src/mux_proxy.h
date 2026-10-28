/* SPDX-License-Identifier: MPL-2.0 */
#ifndef JUICE_MUX_PROXY_H
#define JUICE_MUX_PROXY_H

#include "addr.h"
#include "thread.h"
#include "timestamp.h"

#include <stdbool.h>
#include <stddef.h>

// PROXY protocol v2 on a mux endpoint: the listed relays and the clients they speak for. A header
// alone never routes a client: only a datagram that authenticates for the client's agent does.
// Receiving and committing run on one thread and take the lock only to change what routing reads.
// Routing runs under the lock.
typedef struct mux_proxy mux_proxy_t;

// Whether a client still has an agent that could hear from it. Called where receiving runs.
typedef bool (*mux_proxy_alive_t)(const addr_record_t *client, void *ptr);

// Keeps previous' flows of relays still listed. Returns JUICE_ERR_INVALID if an entry is not a
// numeric address or CIDR range.
int mux_proxy_create(const char *const *relays, size_t count, mutex_t *lock,
                     mux_proxy_alive_t alive, void *alive_ptr, const mux_proxy_t *previous,
                     mux_proxy_t **proxy);
void mux_proxy_destroy(mux_proxy_t *proxy);

// Strips a listed relay's header and attributes the datagram to the client it declares. Returns
// -1 to drop the datagram, 1 when the relay does not route that client yet, with the relay
// written for mux_proxy_commit, or 0.
int mux_proxy_receive(mux_proxy_t *proxy, char **data, size_t *size, addr_record_t *src,
                      addr_record_t *relay, timestamp_t now);

// Whether mux_proxy_commit would route the client through the relay: one still listed, not routing
// another client that is alive, with room for the client. A full table makes room by giving up the
// oldest route of a client that is gone.
bool mux_proxy_admits(mux_proxy_t *proxy, const addr_record_t *relay, const addr_record_t *client);

// Routes the client through the relay, once a datagram the relay brought authenticated for the
// client's agent. Returns -1 unless admitted.
int mux_proxy_commit(mux_proxy_t *proxy, const addr_record_t *relay, const addr_record_t *client,
                     timestamp_t now);

// The relay that routes the client, or NULL
const addr_record_t *mux_proxy_relay(mux_proxy_t *proxy, const addr_record_t *client);

// Where a datagram to dst goes: the relay that routes it, dst itself for a STUN server lookup, or
// NULL to drop it, as nothing else passes the relays
const addr_record_t *mux_proxy_route(mux_proxy_t *proxy, const addr_record_t *dst,
                                     const char *data, size_t size);

#endif
