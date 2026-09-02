// Recovery cursor state: position and retry records.

/// Last fully classified entry in a three-level recovery hierarchy.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ThreeLevelCursor {
    pub(crate) first: Vec<u8>,
    pub(crate) second: Vec<u8>,
    pub(crate) resume_after: Vec<u8>,
}

impl ThreeLevelCursor {
    pub(crate) fn new(first: &[u8], second: &[u8], resume_after: &[u8]) -> Self {
        Self {
            first: first.to_vec(),
            second: second.to_vec(),
            resume_after: resume_after.to_vec(),
        }
    }

    pub(crate) fn should_skip(&self, first: &[u8], second: &[u8], entry: &[u8]) -> bool {
        (first, second, entry)
            <= (
                self.first.as_slice(),
                self.second.as_slice(),
                self.resume_after.as_slice(),
            )
    }
}

/// Last fully classified entry in a four-level recovery hierarchy.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FourLevelCursor {
    pub(crate) first: Vec<u8>,
    pub(crate) second: Vec<u8>,
    pub(crate) third: Vec<u8>,
    pub(crate) resume_after: Vec<u8>,
}

impl FourLevelCursor {
    pub(crate) fn new(first: &[u8], second: &[u8], third: &[u8], resume_after: &[u8]) -> Self {
        Self {
            first: first.to_vec(),
            second: second.to_vec(),
            third: third.to_vec(),
            resume_after: resume_after.to_vec(),
        }
    }

    pub(crate) fn should_skip(
        &self,
        first: &[u8],
        second: &[u8],
        third: &[u8],
        entry: &[u8],
    ) -> bool {
        (first, second, third, entry)
            <= (
                self.first.as_slice(),
                self.second.as_slice(),
                self.third.as_slice(),
                self.resume_after.as_slice(),
            )
    }
}

/// Persisted progress for canonical, restartable recovery phases.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RecoveryPhase {
    #[default]
    ReapLeases,
    PromoteDelayed,
    CleanupTemp,
    CompactReceipts,
    DeleteReceipts,
}

/// The directory operation that must succeed before a retry is resolved.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RecoveryHierarchyRetryKind {
    #[default]
    Open,
    Enumerate,
}

/// A hierarchy directory that must be retried independently of the main cursor.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryHierarchyRetry {
    pub(crate) phase: RecoveryPhase,
    #[serde(default)]
    pub(crate) kind: RecoveryHierarchyRetryKind,
    pub(crate) components: Vec<String>,
}

/// Persisted progress for canonical, restartable recovery phases.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryCursor {
    pub(crate) phase: RecoveryPhase,
    pub(crate) reap_leases: Option<FourLevelCursor>,
    /// Ready shard at which the colocated-lease scan resumes after budget
    /// exhaustion, so earlier shards are not rescanned every pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) reap_colocated_shard: Option<u32>,
    pub(crate) promote_delayed: Option<ThreeLevelCursor>,
    pub(crate) cleanup_temp: Option<ThreeLevelCursor>,
    pub(crate) compact_receipts: Option<ThreeLevelCursor>,
    pub(crate) delete_receipts: Option<ThreeLevelCursor>,
    #[serde(default)]
    pub(crate) hierarchy_retries: Vec<RecoveryHierarchyRetry>,
    #[serde(default)]
    pub(crate) hierarchy_retry_frontiers: Vec<RecoveryHierarchyRetry>,
    #[serde(default)]
    pub(crate) hierarchy_retry_overflow: Vec<RecoveryPhase>,
}
