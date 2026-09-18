# STUN binding observations

An application can keep a STUN binding warm and inspect its latest observation without creating a remote ICE peer. The monitoring agent uses its configured UDP connection. In MUX mode it shares the listener/peer socket when the bind-address spelling and fixed port match exactly.

```c
juice_config_t config = {0};
config.concurrency_mode = JUICE_CONCURRENCY_MODE_MUX;
config.bind_address = bind_address; // Exactly the listener's bind address
config.local_port_range_begin = config.local_port_range_end = local_port;
config.stun_server_host = stun_host;
config.stun_server_port = stun_port;

juice_agent_t *monitor = juice_create(&config);
if (!monitor)
    return -1;
if (juice_set_stun_monitoring(monitor, true) != JUICE_ERR_SUCCESS ||
    juice_gather_candidates(monitor) != JUICE_ERR_SUCCESS) {
    juice_destroy(monitor);
    return -1;
}

// Poll later from application-owned scheduling. No remote description is needed.
juice_stun_binding_t binding;
for (unsigned int index = 0;
     juice_get_stun_binding(monitor, index, &binding) == JUICE_ERR_SUCCESS;
     ++index) {
    // Copy/consume server and mapped addresses, counters, revision and age.
}

// At shutdown; other agents/listeners retain their shared socket ownership.
juice_destroy(monitor);
```

Set monitoring before gathering; changing it after gathering returns `JUICE_ERR_FAILED`. It is disabled by default. Enabled monitoring retains the existing 15-second STUN keepalive cadence, retries after failed initial transactions or server errors, and continues independently of ICE nomination or failure. It does not change peer consent rules.

`juice_get_stun_binding` copies one resolved-server entry under the connection lock. It performs no discovery, network requests, or refresh itself. Each server has a separate observation; reading one family cannot refresh another family. Successful replies must match the outstanding transaction and configured resolved source endpoint and contain a mapped address. Duplicate/completed transactions cannot advance freshness.

- `successful_responses` increases on every accepted response, including unchanged mappings.
- `mapping_revision` starts at zero, becomes one on the first response, and increases only when the mapped address or port changes.
- `last_success_age_ms` measures age using the library clock; it is `UINT64_MAX` before any success. Failed attempts retain the historical mapping and its increasing age.
- `failed_transactions` counts failed sends, exhausted initial retransmissions, server errors, and keepalive transactions still unanswered when the next refresh starts. Individual retransmissions do not increase this count.
- `state` describes the latest transaction: pending, succeeded, or failed. A pending transaction does not invalidate the previous observation by itself.

The application chooses a freshness limit. A recent STUN response is neither a NAT lease nor evidence that an arbitrary client can send to that mapping. Discovery does not establish ICE, DTLS, a data channel, or application-level reachability.

The observation API does not rewrite the accumulated ICE candidate SDP. Consumers needing the current mapped endpoint must use the snapshot instead of treating all previously gathered candidates as current. Existing peers keep their selected pair and identity across observation revisions.

The existing resolver is unchanged: it captures at most two STUN-server results once per agent, without periodic DNS refresh or a guarantee that both families occur in those first results. Applications requiring explicit per-family server selection can resolve/select numeric server endpoints and use separate monitoring agents on the same MUX bind address and fixed port. `JUICE_ERR_NOT_AVAIL` indicates that an index does not currently have a resolved server; it does not distinguish ongoing resolution from resolution failure.

## Local regression tests

```sh
cmake -S . -B build -DWARNINGS_AS_ERRORS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j 4
./build/tests # Windows: build\tests.exe
```

The existing test runner calls `test_stun_monitoring()` on Linux, macOS and Windows; `NO_TESTS=ON` disables the normal test build.

The monitoring tests use real IPv4/IPv6 loopback UDP sockets and fixture STUN responses. They cover initial observations, source/transaction validation, duplicate rejection, server errors with monitoring enabled and disabled, shared-socket ICE data, and independent teardown. They do not wait for periodic refresh, retry or consent expiry, so those timer-driven transitions are outside this test's coverage. No external STUN service or NAT emulator is used. These tests do not establish public-network NAT traversal, DTLS/SCTP compatibility, or game-client behavior.
