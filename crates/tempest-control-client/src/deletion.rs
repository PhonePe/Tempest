// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Exact-target deletion contract. Preview is advisory and never reserves state.

use serde::{Deserialize, Serialize};

use crate::{
    ControlError, ValidateRequest, invalid_request, valid_digest, valid_identifier,
    valid_logical_name,
};

/// Select one retained group/embedded manifest or a root-relative physical file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DeleteTarget {
    /// Removes metadata only; active withdrawal is a separate operation.
    RetainedGroup {
        /// Explicit profile namespace, at most 64 ASCII identifier bytes.
        boot_profile: String,
        /// Retained group identifier, at most 128 ASCII identifier bytes.
        group_id: String,
    },
    /// Advisory only: core currently refuses all byte deletion.
    File {
        /// Physical path relative to the artifact root, at most 255 bytes.
        path: String,
    },
}

impl ValidateRequest for DeleteTarget {
    fn validate(&self) -> Result<(), ControlError> {
        let valid = match self {
            Self::RetainedGroup {
                boot_profile,
                group_id,
            } => valid_identifier(boot_profile, 64) && valid_identifier(group_id, 128),
            Self::File { path } => valid_logical_name(path),
        };
        if valid {
            Ok(())
        } else {
            Err(invalid_request("invalid delete target"))
        }
    }
}

/// Request a side-effect-free, bounded deletion preview.
#[derive(Debug, Clone, Serialize)]
pub struct PreviewDeleteRequest {
    /// Exactly one target; no implicit transitive deletion.
    pub target: DeleteTarget,
}

/// Confirmation must bind the exact identity displayed to the operator.
#[derive(Debug, Clone, Serialize)]
pub struct ConfirmDeleteRequest {
    /// Target returned by preview, unchanged.
    pub target: DeleteTarget,
    /// Opaque lowercase SHA-256 identity returned by preview, unchanged.
    pub expected_identity: String,
}

impl ValidateRequest for ConfirmDeleteRequest {
    fn validate(&self) -> Result<(), ControlError> {
        self.target.validate()?;
        if valid_digest(&self.expected_identity) {
            Ok(())
        } else {
            Err(invalid_request("invalid delete identity"))
        }
    }
}

/// Stable server refusal codes; consumers must also fail closed on unknown codes.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeleteBlocker {
    /// Target is active; explicit withdrawal is required separately.
    ActiveRelease,
    /// A live local boot-session reference exists.
    BootSessionPinned,
    /// An in-flight local transfer reference exists.
    TransferPinned,
    /// Profile deployment or rollback is reserved.
    CutoverInProgress,
    /// Required SQL serving/deletion coordination is disabled or unavailable.
    PersistenceCoordinationUnavailable,
    /// Byte deletion lacks coordinated reader/publication/namespace exclusion.
    ByteDeletionUnavailable,
    /// A retained release refers to these bytes.
    RetainedReference,
    /// Some retained references could not be inspected or remote state may differ.
    ReferenceCheckIncomplete,
    /// Removal would release the last managed logical-name ownership fence.
    OwnershipFenceRequired,
    /// New server blocker unknown to this client; do not permit deletion.
    #[serde(other)]
    Unknown,
}

/// Known retained dependency, bounded to 100 groups per preview.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DeleteGroupReference {
    /// Profile namespace.
    pub boot_profile: String,
    /// Retained group identifier.
    pub group_id: String,
    /// Exact manifest identity for a separate preview/confirmation.
    pub manifest_digest: String,
}

/// Local advisory inventory; never permission to bypass execution revalidation.
#[derive(Debug, Clone, Deserialize)]
pub struct DeletePreview {
    /// Target inspected.
    pub target: DeleteTarget,
    /// Exact confirmation identity, not an authorization token or reservation.
    pub expected_identity: String,
    /// True only for an unblocked retained metadata group. SQL persistence also
    /// requires enabled, healthy coordinated deletion with exclusive serving
    /// ownership; confirmation still revalidates identity and dependencies.
    pub can_delete: bool,
    /// Machine-readable blockers. Re-preview after resolving one; never auto-cascade.
    pub blockers: Vec<DeleteBlocker>,
    /// Known retained file dependencies; empty is not proof of safe unlinking.
    pub referring_groups: Vec<DeleteGroupReference>,
}

/// Successful metadata removal; artifact bytes are always preserved.
#[derive(Debug, Clone, Deserialize)]
pub struct DeleteResult {
    /// Exactly the target removed.
    pub deleted: DeleteTarget,
    /// Confirmed identity removed.
    pub expected_identity: String,
    /// Always false in the current contract.
    pub bytes_deleted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ControlClient;

    #[test]
    fn deletion_unknown_blockers_fail_closed_and_identity_is_preserved() {
        let preview: DeletePreview = serde_json::from_value(serde_json::json!({
            "target": {"kind": "retained_group", "boot_profile": "default", "group_id": "r1"},
            "expected_identity": "a".repeat(64),
            "can_delete": false,
            "blockers": ["future_blocker"],
            "referring_groups": []
        }))
        .unwrap();
        assert_eq!(preview.blockers, vec![DeleteBlocker::Unknown]);
        let confirmation = ConfirmDeleteRequest {
            target: preview.target,
            expected_identity: preview.expected_identity,
        };
        confirmation.validate().unwrap();
        let body = serde_json::to_value(confirmation).unwrap();
        assert_eq!(body["expected_identity"], "a".repeat(64));
        assert_eq!(body["target"]["group_id"], "r1");
    }

    #[tokio::test]
    async fn deletion_invalid_requests_fail_before_transport() {
        let client = ControlClient::new("http://127.0.0.1:9", None).unwrap();
        for path in ["", "../kernel", "/kernel", "a\\b"] {
            assert!(matches!(
                client
                    .preview_delete(&PreviewDeleteRequest {
                        target: DeleteTarget::File { path: path.into() },
                    })
                    .await,
                Err(ControlError::InvalidRequest(_))
            ));
        }
        for identity in ["".into(), "a".repeat(63), "A".repeat(64), "g".repeat(64)] {
            assert!(matches!(
                client
                    .confirm_delete(&ConfirmDeleteRequest {
                        target: DeleteTarget::File {
                            path: "kernel".into()
                        },
                        expected_identity: identity,
                    })
                    .await,
                Err(ControlError::InvalidRequest(_))
            ));
        }
    }
}
