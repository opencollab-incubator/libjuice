# Per-agent UDP send limits

This optional generic primitive bounds actual mux UDP sends. No caller enables it by default. Player agents, listener interruption packets and separate STUN monitor agents retain their existing behavior.

Install `juice_set_udp_send_limits` once before gathering, with positive datagram/payload limits and an absolute `deadline_monotonic_ms` in the clock returned by `juice_monotonic_time_ms`. Capture that deadline before delayed admission/peer preparation; never recompute it when attaching another tuple. Installation copies the optional numeric destination into owned address storage. DNS, zone identifiers, wildcard destinations and ambiguous IPv4-mapped IPv6 input are rejected. No destination means all UDP destinations still share the same agent budget.

The initial implementation supports mux UDP only. Non-mux agents, enabled ICE TCP and local TURN servers reject installation; enabling those paths afterward also rejects. Configuration/installation must be serialized before gathering, like local ICE attributes. Existing configuration structs and default behavior remain unchanged.

Every agent-associated call to the physical mux UDP send path passes the guard, including ICE checks/responses, STUN discovery, retransmissions, DTLS and SCTP. The shared socket send lock is acquired before checking the deadline. A separate agent lock makes reservation, OS send and the statistics snapshot atomic. A reserved send consumes quota even when `sendto` fails. Rejected sends do not reach the socket; counters record the last rejection reason. Oversized or wrong-destination packets do not consume datagram quota, but do increment the rejection count. An expired/exhausted agent cannot regain quota. The caller owns closing it and any higher protocol state; installing limits does not authenticate a workload or a peer.

`juice_get_udp_send_stats` returns an owned atomic snapshot. `reserved_datagrams` counts OS send attempts; `sent_datagrams`/`sent_bytes` count successful system calls, not delivery. `rejected_datagrams` saturates at UINT64_MAX. The configured uint32 datagram count and UDP payload bounds prevent successful counters from overflowing. Unlimited agents return NOT_AVAIL and acquire no per-agent budget lock while sending.

Linux regression tests use real loopback UDP for IPv4 and IPv6. They verify concurrent sends cannot exceed quota, the exact 1200-byte boundary, destination and absolute expiry checks, failed OS attempts, actual STUN retransmission suppression, and an unlimited agent using the same mux after the limited agent exhausts its quota. The latter is native socket isolation evidence; a simultaneous full player admission is a separate Network integration gate.

```
cmake -S . -B ../build-libjuice -DNO_TESTS=ON -DPENDING_MUX_TESTS=ON -DSTUN_MONITORING_TESTS=ON -DUDP_SEND_LIMIT_TESTS=ON -DENABLE_LOCALHOST_ADDRESS=ON -DCMAKE_BUILD_TYPE=Debug -DWARNINGS_AS_ERRORS=ON
cmake --build ../build-libjuice -j 4
ctest --test-dir ../build-libjuice --output-on-failure
```

These tests do not establish native platform release readiness, a signed diagnostic host gate, remote reachability, client login or gameplay.
