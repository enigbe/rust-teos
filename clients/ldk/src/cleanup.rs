/// Result of explicitly cleaning one pending appointment. Historical receipts,
/// coverage observations and the delivery record are preserved in every case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupOutcome {
    /// The validated, completed pending job was removed.
    Removed,
    /// No pending job exists for this channel and commitment.
    AlreadyAbsent,
    /// Evidence is incomplete, or the worker still has unresolved work. Inspect
    /// coverage/delivery diagnostics and drive the worker before trying again.
    Retained,
}
