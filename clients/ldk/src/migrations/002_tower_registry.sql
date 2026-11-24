-- Version 2: persist connection settings independently of registration evidence.
CREATE TABLE tower_registry (
    tower_id BLOB PRIMARY KEY NOT NULL CHECK (length(tower_id) = 33),
    endpoint TEXT NOT NULL,
    timeout_seconds INTEGER NOT NULL CHECK (timeout_seconds >= 0),
    timeout_nanoseconds INTEGER NOT NULL CHECK (timeout_nanoseconds BETWEEN 0 AND 999999999)
);
