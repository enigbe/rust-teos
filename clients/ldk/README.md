# LDK watchtower client

An embedded TEOS watchtower client for LDK-based nodes, providing persistent
appointments, verified tower receipts, delivery retries, and explicit `ToLocalOnly`
protection.

## Tests

Run the normal client suite from the workspace root:

```sh
cargo test -p ldk-watchtower-client --locked
```

The real-node integration harness is opt-in:

```sh
cargo test -p ldk-watchtower-client --locked \
  --features integration-tests --test chainmonitor
```

The `integration-tests` feature enables the pinned LDK revision's internal
`_test_utils` feature. It builds two in-process Lightning nodes and a real
`ChainMonitor`, increasing build time and adding the native `bitcoinconsensus`
C++ dependency. Keep this feature off in applications embedding the client.
It requires no changes to an LDK checkout.

The harness runs separate legacy and anchor-channel tests against a mock HTTP
tower with signed receipts. Each test:

- Opens a channel and makes payments that revoke both HTLC-free and
  HTLC-bearing commitments, using LDK-generated justice transactions.
- Delivers a commitment containing both to_local and HTLC claims first, saves
  its receipt, and simulates a restart before LDK consumes the acknowledgment.
- Reloads the serialized channel monitor into a fresh `ChainMonitor` and reopens
  the client database. The saved receipt satisfies delivery without another
  network request; remaining appointments are delivered from their saved payloads.
- Calls `ChainMonitor::release_pending_monitor_events` to consume acknowledgments
  through LDK's normal path and verifies that watchtower retention is empty.
- Reopens the database again and verifies receipts, unchanged appointment payloads,
  and durable coverage records, including the deliberately excluded HTLC claims.

## Live regtest TEOS

The live test repeats the scenario for both legacy and anchor channels against
an existing regtest `teosd`, backed by a synced
regtest Bitcoin node. Start these services separately and obtain the tower's
compressed public key from its `tower_id:` startup log. Configure the public HTTP
API URL, rather than the administrative gRPC endpoint:

```sh
TEOS_E2E_URL=http://127.0.0.1:9814 \
TEOS_E2E_TOWER_ID=YOUR_COMPRESSED_TOWER_PUBLIC_KEY \
cargo test -p ldk-watchtower-client --locked \
  --features integration-tests --test chainmonitor \
  live_teos_chainmonitor_delivery_and_restart -- --ignored --exact
```

This test explicitly registers a fresh client identity and consumes subscription
slots on the selected tower. Use a disposable regtest tower. The client database
is temporary and removed after the test; tower-side registrations and appointments
remain until the tower expires them or its disposable data directory is removed.
Missing configuration fails the explicitly requested test instead of skipping it.

The Lightning nodes use LDK's simulated chain fixtures. The live test verifies
registration, submission, signed receipt persistence, restart recovery, and LDK
acknowledgment against real services. It does not publish a revoked commitment or
prove that the tower broadcasts a successful on-chain justice transaction.
