-- Version 1: frozen baseline of the complete unversioned client schema.
CREATE TABLE client_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    secret_key BLOB NOT NULL CHECK (length(secret_key) = 32)
);
CREATE TABLE registrations (
    tower_id BLOB NOT NULL,
    user_id BLOB NOT NULL,
    available_slots INTEGER NOT NULL,
    subscription_start INTEGER NOT NULL,
    subscription_expiry INTEGER NOT NULL,
    signature TEXT NOT NULL,
    PRIMARY KEY (tower_id, user_id, subscription_expiry)
);
CREATE TABLE pending_appointments (
    channel_id BLOB NOT NULL CHECK (length(channel_id) = 32),
    commitment_txid BLOB NOT NULL CHECK (length(commitment_txid) = 32),
    user_id BLOB NOT NULL CHECK (length(user_id) = 33),
    locator BLOB NOT NULL CHECK (length(locator) = 16),
    encrypted_blob BLOB NOT NULL,
    to_self_delay INTEGER NOT NULL,
    signature TEXT NOT NULL,
    PRIMARY KEY (channel_id, commitment_txid)
);
CREATE TABLE appointment_receipts (
    tower_id BLOB NOT NULL,
    channel_id BLOB NOT NULL,
    commitment_txid BLOB NOT NULL,
    user_signature TEXT NOT NULL,
    start_block INTEGER NOT NULL,
    tower_signature TEXT NOT NULL,
    PRIMARY KEY (tower_id, channel_id, commitment_txid, start_block)
);
CREATE INDEX appointment_receipts_by_commitment
    ON appointment_receipts (channel_id, commitment_txid);
CREATE TABLE delivered_appointments (
    channel_id BLOB NOT NULL CHECK (length(channel_id) = 32),
    commitment_txid BLOB NOT NULL CHECK (length(commitment_txid) = 32),
    client_signature TEXT NOT NULL,
    claim_fingerprint BLOB NOT NULL CHECK (length(claim_fingerprint) = 32),
    PRIMARY KEY (channel_id, commitment_txid)
);
CREATE TABLE latest_coverage (
    channel_id BLOB NOT NULL CHECK (length(channel_id) = 32),
    commitment_txid BLOB NOT NULL CHECK (length(commitment_txid) = 32),
    coverage_id INTEGER,
    PRIMARY KEY (channel_id, commitment_txid)
);
CREATE TABLE coverage_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id BLOB NOT NULL CHECK (length(channel_id) = 32),
    commitment_txid BLOB NOT NULL CHECK (length(commitment_txid) = 32),
    scope INTEGER NOT NULL,
    feerate_per_kw INTEGER NOT NULL CHECK (feerate_per_kw > 0),
    to_local INTEGER NOT NULL CHECK (to_local IN (0, 1)),
    excluded_htlc_claims INTEGER NOT NULL CHECK (excluded_htlc_claims >= 0),
    unclassified_claims INTEGER NOT NULL CHECK (unclassified_claims >= 0),
    stored_claim_matches INTEGER NOT NULL CHECK (stored_claim_matches IN (0, 1)),
    client_signature TEXT NOT NULL,
    required_towers BLOB NOT NULL,
    completion_ready INTEGER NOT NULL DEFAULT 0 CHECK (completion_ready IN (0, 1)),
    UNIQUE (channel_id, commitment_txid, scope, feerate_per_kw, to_local,
        excluded_htlc_claims, unclassified_claims, stored_claim_matches, client_signature, required_towers)
);
