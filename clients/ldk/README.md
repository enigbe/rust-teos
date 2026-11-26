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

During configuration, save each tower's identity, HTTP URL and request timeout
with `ClientStore::save_tower`. For startup, supply the same database path and an
explicit list of saved IDs in `Settings::required_towers`, together with the
justice fee rate in sat/kw, sweep destination script,
`ProtectionScope::ToLocalOnly`, and registration action. The helper loads only
those selected entries; it does not activate every tower in the registry.

Use this startup order:

1. Call `open_watchtower(settings)`. All selected settings and the worker
   configuration are validated before creating an identity or registering.
   Missing or corrupt selected entries fail startup; other registry entries do
   not affect this selection. Choose `RegisterOrRenew` only for an explicit
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
Reuse the same database and signing identity on restart. Fee and destination
changes do not replace already prepared or delivered payloads. Every currently
required tower still needs a matching receipt when replaying completed delivery.
The fee rate is fixed for each worker; an already prepared commitment keeps its
original payload even if a later worker uses a different fee rate.

## Registration and subscription operations

`TowerClient::register(&mut store)` explicitly registers or renews the persisted
identity. It verifies and saves the signed receipt before returning success, and
never retries automatically. `RegistrationError::Rejected` preserves the HTTP
status, optional tower error code, and a bounded message. A malformed HTTP 200
reply returns `InvalidResponse`; a body-transfer failure returns `ResponseRead`
with the received status. HTTP 200 bodies are limited to 16 KiB; rejection bodies
and messages to 4 KiB. These methods share response handling with appointment
submission.

`TowerClient::subscription_info(&identity)` signs the protocol's subscription
query with an identity obtained from `ClientStore::load_or_create_identity`.
The request does not borrow storage, register, renew, retry, or rearm delivery.
`SubscriptionInfo` reports remaining slots, expiry height, and typed appointment
locators. The protocol supplies no subscription start height in this response.

The report is unsigned and remains separate from signed registration and
appointment receipts. It does not establish delivery or authorize LDK
acknowledgment, and the query never overwrites stored evidence. Bodies are
limited to 1 MiB by default, covering about 30,000 locators. Use
`subscription_info_with_limit(&identity, limit)` with a `NonZeroUsize` byte limit
for larger successful reports. Rejection bodies and messages remain capped at
4 KiB independently of that limit. Allow about 35 JSON bytes per expected locator
plus headroom; the remaining slot count in a registration receipt cannot size
this list.
Oversized reports fail explicitly instead of returning a partial list. Malformed
locators also fail the query.
Subscription errors preserve tower rejection details and distinguish transport,
body-transfer, and decoding failures. The application decides whether to renew
or investigate a rejection; subscription queries do not choose a recovery policy.

## Saved towers

`ClientStore::save_tower(&config)` persists a validated `TowerConfig`, keyed by
the tower's public identity. Saving the same ID updates only its HTTP endpoint
and request timeout. `tower(id)` loads one entry and `towers()` lists entries in
compressed-public-key byte order. Timeout seconds and nanoseconds are stored as
plain SQLite integers without rounding. `TowerConfig::new` rejects seconds above
`i64::MAX` with `TowerConfigError::TimeoutTooLarge`.

Saving settings does not contact the tower, register or renew a subscription,
create a client identity, or change registration receipts and appointments.
Registration remains an explicit `TowerClient::register` operation. A saved entry
does not establish that a tower has registered the user or protects any commitment.

The embedding example loads the IDs in `Settings::required_towers` from this
registry. Saving or updating an entry does not reconfigure an existing worker;
reopening the worker loads the current connection settings for the selected IDs.
Loading validates the public key, URL, and nonzero timeout again; invalid selected
entries return an error instead of being silently omitted from the required tower
set. Reopening with `UseSavedReceipts` does not register again, even if an endpoint
or timeout changed. Choose renewal explicitly when it is needed.

`ClientStore::remove_tower(id)` removes only the saved connection settings and
returns whether an entry was removed. Repeated removal returns `false`. It keeps
the client identity, registration receipts, pending appointments, coverage
history, and delivery evidence. It neither contacts the tower nor cancels the
appointments already stored there.

Removal does not change a running worker or cancel its in-flight requests. To
retire a tower from delivery, explicitly change `Settings::required_towers` and
rebuild the worker. Keeping a removed ID selected makes startup fail, rather than
silently weakening the required-tower set. Removal does not erase receipts needed
for historical verification or replay.

## Database versions and migrations

The dedicated client database uses SQLite's `PRAGMA user_version`. The current
schema version is 2. `ClientStore::open` initializes or upgrades the schema before
returning; it does not generate a signing identity during initialization.

An empty database is initialized atomically. The known complete unversioned client
layout is adopted as version 1 and upgraded without rewriting existing rows,
re-signing payloads, or changing coverage IDs and autoincrement state. Partial or
unrelated unversioned layouts are rejected rather than completed by guessing
which tables are missing.
Migration does not infer a cleanup decision from old coverage observations.

Unsupported versions return `StorageError::UnsupportedSchemaVersion`. A layout
which does not match the supported client schema returns `StorageError::InvalidSchema`,
including missing tables, changed definitions, or an incompatible required index.
These failures do not initialize or repair the existing database. Additional
indexes and triggers on the client's own tables are preserved; required definitions
must still match the frozen schema.

The baseline is frozen in `src/migrations/001_initial.sql`. Version 2 adds an empty
tower registry through `002_tower_registry.sql`; it does not infer connection
settings from registration receipts. Future changes append ordered migrations
to the schema module instead of editing previously supported versions.
Migration SQL must not manage its own transactions. All pending steps,
including their version markers, run in one immediate transaction: a failure
rolls the entire upgrade back, so it can be retried after the cause is resolved.
Concurrent openers recheck the version after acquiring the write lock. Already
current databases are checked using a read transaction without a write lock.

Initialize storage before loading monitors or starting the worker, as in the
embedding example. Do not keep older client processes running against a database
being upgraded by a newer client. The version-1 baseline preserves the existing
appointment and claim fingerprint formats.

## Historical receipts

`ClientStore::appointment_receipt` verifies the tower's signature using the stored
client signature and start block. It remains usable after the pending job or
client signing key is unavailable. Tower, channel, and full commitment IDs remain
the local lookup association established when saving against an unchanged job.
The tower signs the client signature and start block, not those lookup IDs.

A historical receipt identifies the submitted payload by its client signature;
it does not include the payload bytes or prove that a current job matches it.
Saving receipts and authorizing acknowledgments still check the expected job.
## Re-offers after a completed payload is removed

Before queuing an acknowledgment for a delivered `to_local` claim, the worker
saves a `delivered_appointments` record in the same transaction as scope completion.
It associates the frozen client signature with a claim fingerprint.
It matches the pending-payload policy: outpoint, revocation script and CSV
delay. A changed fee or sweep destination does not invalidate the original
delivered transaction. These are local recovery metadata, not extra tower-signed
data; the tower receipt remains bound to the original client signature.

If a pending payload is missing but delivery history exists, replay checks that
record before preparing anything. A supplied `to_local` claim must match its
fingerprint, and unclassified claims always block. A completed observation for
the same scope and client signature must exist. Every currently required tower
must have a valid receipt for that signature; the tower set need not match the
old observation. Removing a tower therefore does not invalidate the remaining
receipts. An added tower without a matching receipt blocks replay.

If LDK omits the claim at the current fee, replay retains the verified delivery
evidence and records the current no-claim or HTLC-only observation. It still checks
every current tower's receipt. The original `to_local` delivery observation and
signature are preserved. The payload is never recreated or sent again.
Repeated identical replays reuse their coverage observation.

`ReofferBlocked` reports changed revocable claims, missing delivery records,
incomplete coverage, or missing/invalid receipts. Restore evidence and submit a
fresh complete snapshot after resolving the reason. The direct
`prepare_appointment` API also refuses replacement preparation when there is
history but no pending payload, including inside its write transaction.

The fingerprint hash includes the `teos/claim/v1` domain tag, so a future format
can be distinguished from this one. Future format changes will require a schema
migration.

Deliveries predating the delivery-record table acquire records when a valid
pending payload is next processed; missing payloads without such a record block.
Receipts, coverage observations and delivery records remain available after
pending-job cleanup. Historical evidence retention remains a follow-up.

## Explicit cleanup

Call `worker.cleanup_completed_appointment(channel_id, commitment_txid)` from the
worker-owning task, after processing queued snapshots and network completions.
The operation makes no network request and never runs from LDK's callback. It is
explicit and handles one job at a time; the embedding loop does not invoke it
automatically. An administrative command branch in that loop can call it.

The result is one of:

- `CleanupOutcome::Removed`: the completed pending payload was deleted.
- `CleanupOutcome::AlreadyAbsent`: no pending job exists; retrying cleanup is safe.
- `CleanupOutcome::Retained`: evidence or the current decision is incomplete, or
  the worker still has unresolved snapshots, signer failures, or delivery state.
  Inspect the existing coverage/delivery events and drive the worker before retrying.

If validation detects corrupt or mismatched evidence, or SQLite fails, the
operation returns `StorageError` without deleting the job. The checks and deletion
share an immediate transaction: the pending job must validate, its signature and claim fingerprint must match the
delivery record, the latest coverage decision must be complete in the current
scope, and every currently required tower must have a valid receipt for that
payload. A latest no-claim observation is allowed only when the original completed
`to_local` observation remains available as replay evidence.

The additive `latest_coverage` table records the most recently observed coverage
ID, including when an older deduplicated observation is reused. IDs alone do not
establish observation order. Failed offers invalidate the decision; unresolved
worker errors also prevent cleanup. Existing jobs without a tracked current
decision are retained until a valid observation is processed. Cleanup does not
infer eligibility from an older successful observation or from receipt existence.

Only the selected row in `pending_appointments` is removed. The signing identity,
receipts, delivery record, coverage history and current decision remain intact.
Cleanup neither queues an acknowledgment nor requires LDK to have consumed one:
if a crash re-offers the commitment, replay rechecks the evidence without creating
or sending another payload. Closed-channel evidence deletion and batch cleanup scheduling
are separate operations and are not implemented here.

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
  its receipt, removes that completed pending payload through the public cleanup
  API, and
  restarts at a different justice fee before LDK consumes the acknowledgment.
- Reloads the serialized channel monitor into a fresh `ChainMonitor` and reopens
  the client database. The saved receipt satisfies delivery without another
  network request or re-preparation; remaining appointments use their saved payloads.
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

## Live on-chain breaches

The `onchain_breach` test target exercises legacy and anchor channels with real
regtest UTXOs. Each scenario confirms the funding transaction, checks that both
peers negotiated the requested channel type, and makes payments through two LDK
nodes. It captures a signed commitment before a later payment revokes it, then
delivers the LDK-generated `to_local` justice appointment to TEOS and verifies its
receipt and normal ChainMonitor acknowledgment.

The published commitment must have two 330-sat P2WSH anchor outputs for the anchor
case and none for the legacy case.

Both LDK nodes and the worker are dropped before the revoked commitment is
broadcast. Their broadcasters only record transactions and have no Bitcoin RPC
connection. The test itself broadcasts funding and the revoked commitment; it
never submits the justice transaction. It waits for TEOS to broadcast the exact
saved justice transaction, then checks that it confirms, pays the sweep script,
and spends the breached output.
The LDK fixtures are configured for regtest and receive actual Bitcoin blocks.
Bitcoin validates the funding, revoked commitment, and justice spends.

With wallet-enabled `bitcoind` and `bitcoin-cli` on `PATH`, run from the project root:

```sh
cargo build -p teos --bin teosd --locked
python3 clients/ldk/tests/run_onchain_breach.py
```

The runner compiles the test with the `integration-tests` feature before starting
services, so compilation is outside the execution timeout. The first build may
fetch dependencies, including the pinned LDK revision; offline mode is not forced.
It then starts isolated localhost regtest Bitcoin and TEOS services with separate
free ports for Bitcoin RPC, both TEOS RPC interfaces, and HTTP. It sets the tower's
polling interval to one second and runs both ignored tests sequentially on that
chain, each with a fresh wallet, signing identity, and client database. It stops
both services and removes their temporary data on success or failure. Use
`--teosd /path/to/teosd` to select another binary. It does not use existing node data
directories or real funds.

To run the ignored test directly against disposable services, provide
`TEOS_E2E_URL`, `TEOS_E2E_TOWER_ID`, `TEOS_E2E_BITCOIN_RPC_URL`,
`TEOS_E2E_BITCOIN_RPC_USER`, and `TEOS_E2E_BITCOIN_RPC_PASSWORD`, then run:

```sh
cargo test -p ldk-watchtower-client --locked --features integration-tests \
  --test onchain_breach -- --ignored --test-threads=1
```

Each test checks the Bitcoin network is regtest before creating a wallet or mining.
A direct run creates wallets, mines blocks, and consumes tower subscription slots;
use disposable services. Run the cases sequentially because they mine on the same
chain. To run only one case, insert `live_teos_legacy_breach` or
`live_teos_anchor_breach` before `--` in the command above. Both scenarios cover
`to_local` recovery; they do not test HTLC recovery.

An existing Docker Compose regtest stack can also supply these services. Set
`polling_delta = 1` in TEOS's `teos.toml`, wait for its HTTP API to be ready, and
use the environment variables above to run the Rust test directly. Manage that
stack's state and lifecycle separately; the isolated runner remains the primary
reproducible test command.
