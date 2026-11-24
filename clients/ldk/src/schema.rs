//! Schema initialization and ordered migrations for the dedicated client database.

use rusqlite::{Connection, TransactionBehavior};

use crate::StorageError;

// Entry n upgrades version n to n+1. Freeze existing entries; append new ones.
// Migration SQL must not contain its own transaction control. All pending steps
// and user_version are committed together under one immediate transaction.
const MIGRATIONS: &[&str] = &[
    include_str!("migrations/001_initial.sql"),
    include_str!("migrations/002_tower_registry.sql"),
];
const SELECT_VERSION: &str = "PRAGMA user_version";
const SELECT_SCHEMA: &str = "SELECT type, name, tbl_name, sql FROM sqlite_master
WHERE name NOT GLOB 'sqlite_*' ORDER BY type, name";

#[derive(Debug, PartialEq, Eq)]
struct Object {
    kind: String,
    name: String,
    table: String,
    sql: Option<String>,
}

fn version(connection: &Connection) -> Result<i64, StorageError> {
    Ok(connection.query_row(SELECT_VERSION, [], |row| row.get(0))?)
}

fn supported(version: i64, latest: i64) -> Result<(), StorageError> {
    if !(0..=latest).contains(&version) {
        return Err(StorageError::UnsupportedSchemaVersion {
            found: version,
            supported: latest,
        });
    }
    Ok(())
}

fn objects(connection: &Connection) -> Result<Vec<Object>, StorageError> {
    let mut statement = connection.prepare(SELECT_SCHEMA)?;
    let rows = statement.query_map([], |row| {
        Ok(Object {
            kind: row.get(0)?,
            name: row.get(1)?,
            table: row.get(2)?,
            sql: row.get(3)?,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

fn validate(connection: &Connection, migrations: &[&str], at: i64) -> Result<(), StorageError> {
    // Compare SQLite's stored definitions with the frozen DDL rather than a
    // second handwritten description of columns, checks, defaults and unique keys.
    let expected = Connection::open_in_memory()?;
    for sql in migrations.iter().take(at as usize) {
        expected.execute_batch(sql)?;
    }
    let expected = objects(&expected)?;
    let actual = objects(connection)?;
    for required in &expected {
        if !actual.iter().any(|object| object == required) {
            return Err(StorageError::InvalidSchema);
        }
    }
    for object in &actual {
        if expected.iter().any(|required| required == object) {
            continue;
        }
        // Auxiliary indexes and triggers on owned tables are preserved. This also
        // permits diagnostic/failure-injection triggers without weakening checks
        // on the required tables or named indexes themselves.
        let owned_table = expected
            .iter()
            .any(|required| required.kind == "table" && required.name == object.table);
        let required_name = expected
            .iter()
            .any(|required| required.kind == object.kind && required.name == object.name);
        if required_name || !owned_table || !matches!(object.kind.as_str(), "index" | "trigger") {
            return Err(StorageError::InvalidSchema);
        }
    }
    Ok(())
}

pub(crate) fn initialize(connection: &mut Connection) -> Result<(), StorageError> {
    initialize_with(connection, MIGRATIONS)
}

fn initialize_with(connection: &mut Connection, migrations: &[&str]) -> Result<(), StorageError> {
    let latest = migrations.len() as i64;
    if latest == 0 {
        return Err(StorageError::InvalidSchema);
    }
    {
        // Version and layout must come from the same read snapshot. Already
        // current databases need no write lock or schema-mutating statements.
        let read = connection.transaction()?;
        let current = version(&read)?;
        supported(current, latest)?;
        if current == latest {
            validate(&read, migrations, current)?;
            read.commit()?;
            return Ok(());
        }
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    // Another opener may have initialized/upgraded while we waited for the lock.
    let mut current = version(&transaction)?;
    supported(current, latest)?;
    if current == 0 {
        if objects(&transaction)?.is_empty() {
            transaction.execute_batch(migrations[0])?;
        } else {
            // Adopt only the known complete unversioned baseline. Do not fill
            // holes in an unknown, partial, or damaged database.
            validate(&transaction, migrations, 1)?;
        }
        current = 1;
        transaction.pragma_update(None, "user_version", current)?;
    } else {
        validate(&transaction, migrations, current)?;
    }
    for (index, sql) in migrations.iter().enumerate().skip(current as usize) {
        transaction.execute_batch(sql)?;
        transaction.pragma_update(None, "user_version", (index + 1) as i64)?;
    }
    validate(&transaction, migrations, latest)?;
    transaction.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_migration_chain_rolls_back_ddl_data_and_version_then_can_retry() {
        let mut db = Connection::open_in_memory().unwrap();
        initialize_with(&mut db, &MIGRATIONS[..1]).unwrap();
        db.execute(
            "INSERT INTO client_identity VALUES (1, ?1)",
            [&[1u8; 32][..]],
        )
        .unwrap();
        let before = objects(&db).unwrap();
        let next = "CREATE TABLE migration_probe (value INTEGER);";
        let broken = "UPDATE client_identity SET secret_key=zeroblob(32); INSERT INTO missing_table VALUES (1);";
        assert!(initialize_with(&mut db, &[MIGRATIONS[0], next, broken]).is_err());
        assert_eq!(version(&db).unwrap(), 1);
        assert_eq!(objects(&db).unwrap(), before);
        let key: Vec<u8> = db
            .query_row("SELECT secret_key FROM client_identity", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(key, vec![1; 32]);
        let repaired = "INSERT INTO migration_probe VALUES (7);";
        initialize_with(&mut db, &[MIGRATIONS[0], next, repaired]).unwrap();
        assert_eq!(version(&db).unwrap(), 3);
        initialize_with(&mut db, &[MIGRATIONS[0], next, repaired]).unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM migration_probe", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1,
            "completed migrations must not execute again"
        );
    }
}
