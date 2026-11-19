# LDK watchtower client

An embedded TEOS watchtower client for LDK-based nodes, providing persistent
appointments, verified tower receipts, delivery retries, and explicit `ToLocalOnly`
protection.

## Embedding in an LDK application

[examples/embedding.rs](examples/embedding.rs) is a compile-checked wiring reference,
not a standalone Lightning node. Its entry point only prints instructions; the
application calls its three public helpers with its existing node dependencies.
It requires no `integration-tests` feature:

```sh
cargo check -p ldk-watchtower-client --locked --example embedding
```

The application supplies a persistent database path, tower identities and HTTP
URLs, request timeouts, a justice fee rate in sat/kw, and its sweep destination
script. `Settings` also requires an explicit `ProtectionScope::ToLocalOnly` and
registration action. The helper validates the worker configuration before making
registration requests.

Use this startup order:

1. Call `open_watchtower(settings)`. Choose `RegisterOrRenew` only for an explicit
   registration or renewal operation. Routine startup uses `UseSavedReceipts`,
   which loads and verifies registration evidence from the same database. An old
   receipt does not establish that the subscription is still active: compare its
   expiry with chain height and handle tower rejections before choosing to renew.
   Registration errors return to the caller without automatic retries. With
   multiple towers, earlier registrations may already have succeeded and been
   saved when a later one fails. Inspect the saved receipts and retry only the
   remaining towers; repeating the whole operation renews successful towers again.
2. Call `install_adapter(node_dependencies, worker.adapter())` and retain the
   resulting `ChainMonitor`. Supply the application's real persistence, filter,
   broadcaster, fee estimator, logger, entropy source, peer-storage key, and
   deferred-update choice. Install the adapter before restoring monitors through
   LDK's normal load path; retained commitments will be offered again on startup.
3. Use that monitor in the application's `ChannelManager` and keep normal LDK
   background event processing running. LDK consumes queued watchtower
   acknowledgments through its monitor-event path; do not drain them separately.
4. Drive `run_worker(&mut worker, concurrency, shutdown)` on the application's
   Tokio runtime. `concurrency` is a `NonZeroUsize` limit on active HTTP sends.
   The loop polls at startup, on adapter notifications, and at coordinator retry
   deadlines. Preparation, coverage, and recovery failures are rechecked after
   five seconds so repaired storage can make progress without a busy loop.

The loop owns queued attempts and runs HTTP requests without borrowing storage.
SQLite access stays on the worker task and is synchronous. A node requiring
strict runtime latency can dedicate a runtime thread to the worker. Polling can
still discover a large number of jobs at once; limiting active sends does not
limit the size of that discovery batch. A corrupt saved receipt also causes a
recheck and repeated diagnostics every five seconds until repaired; this example
does not quarantine invalid evidence or stop rechecking it automatically.

Replace stderr reporting with the node's operator events and metrics. Coverage
reports identify excluded HTLC claims and unclassified claims; an absent generated
`to_local` claim may be fee-dependent. Every configured tower is required for an
applicable claim. Non-retryable failures and exhausted retry windows with
automatic rearming disabled are reported for intervention. An application can add
a command branch to the loop and call
`worker.retry_job` after storage repair or an explicit registration renewal; a
new poll alone does not rearm these stopped jobs.

For shutdown, stop new channel activity, signal the worker, and keep LDK event
processing alive while active HTTP requests finish. The loop drops waiting
attempts, drains admitted sends through `worker.finish`, and returns with the worker
still available. Inspect `worker.unsaved_receipts()` before dropping it: verified
receipts which could not be saved exist only in memory. After repairing storage,
clone the needed receipts before borrowing the store. Save them through
`worker.store_mut().save_appointment_receipt`, or resume the worker's save retries.
Then persist the application's LDK state and shut it down normally. A crash before
the next monitor persist may re-offer acknowledged commitments. Saved appointments
and receipts make that recovery idempotent.
Reuse the same database, sweep configuration, and required tower set on restart.
The fee rate is fixed for each worker; an already prepared commitment keeps its
original payload even if a later worker uses a different fee rate.

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

The embedding-loop tests load the monitor only after the worker's initial poll,
so snapshot processing requires a wake notification. A separate case returns one
HTTP 503 before accepting an appointment; delivery must resume at its retry
deadline without another snapshot notification.

## Live regtest TEOS

The live test repeats the scenario for both legacy and anchor channels against
an existing regtest `teosd`. The legacy case drives attempts manually and checks
that the saved appointment is not resent. The anchor case uses the embedding
example's worker loop. The tower must be backed by a synced regtest Bitcoin
node. Start these services separately
and obtain the tower's compressed public key from its `tower_id:` startup log.
Configure the public HTTP API URL, rather than the administrative gRPC endpoint:

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
