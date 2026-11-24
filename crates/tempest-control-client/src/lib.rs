// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Typed client for Tempest's vendor-neutral HTTP control plane.
//!
//! Provisioning systems use this crate to stage release metadata and register
//! boot sessions. The client does not assume any particular orchestrator.

use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::path::{Component, Path};
use std::time::Duration;

use reqwest::header::CONTENT_TYPE;
use reqwest::{Method, StatusCode, Url};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DEPLOYMENT_TIMEOUT: Duration = Duration::from_secs(310);
const MAX_ERROR_BODY_BYTES: usize = 4 * 1024;
const MAX_JSON_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;

mod deletion;
pub use deletion::{
    ConfirmDeleteRequest, DeleteBlocker, DeleteGroupReference, DeletePreview, DeleteResult,
    DeleteTarget, PreviewDeleteRequest,
};

/// Errors returned by [`ControlClient`].
#[derive(Debug, Error)]
pub enum ControlError {
    /// The configured API base URL was invalid or unsupported.
    #[error("invalid Tempest API URL: {0}")]
    InvalidUrl(String),
    /// A request violated Tempest's public control-plane bounds.
    #[error("invalid Tempest API request: {0}")]
    InvalidRequest(String),
    /// A JSON request exceeded the client's serialization budget.
    #[error("Tempest API request exceeded {limit} bytes")]
    RequestTooLarge {
        /// Maximum accepted request body size.
        limit: usize,
    },
    /// HTTP transport or response decoding failed.
    #[error("Tempest API transport failed: {0}")]
    Transport(#[from] reqwest::Error),
    /// A successful JSON response exceeded the client's memory budget.
    #[error("Tempest API response exceeded {limit} bytes")]
    ResponseTooLarge {
        /// Maximum accepted response body size.
        limit: usize,
    },
    /// A successful response was not valid JSON for the requested type.
    #[error("Tempest API response decoding failed: {0}")]
    Decode(#[from] serde_json::Error),
    /// The server returned a non-success status.
    #[error("Tempest API returned HTTP {status}: {message}")]
    Api {
        /// HTTP response status.
        status: StatusCode,
        /// Bounded response message.
        message: String,
    },
}

/// One active or historical artifact version returned by Tempest.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct VersionInfo {
    /// Boot-profile namespace.
    pub boot_profile: String,
    /// Logical artifact name.
    pub name: String,
    /// Process-local version identifier.
    pub version_id: u64,
    /// SHA-256 content hash.
    pub content_hash: String,
    /// Artifact size in bytes.
    pub size: u64,
}

/// Bounded control-plane response with an optional continuation cursor.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Page<T> {
    /// Items in this page.
    pub items: Vec<T>,
    /// Opaque cursor for the next page.
    pub next_cursor: Option<String>,
}

/// Version-group and manifest metadata returned by Tempest.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct GroupInfo {
    /// Boot-profile namespace.
    pub boot_profile: String,
    /// Operator-supplied release identifier.
    pub group_id: String,
    /// Process-local version identifier shared by group members.
    pub version_id: u64,
    /// Artifacts belonging to the release.
    pub files: Vec<VersionInfo>,
    /// RFC 3339 creation time.
    pub created_at: String,
    /// SHA-256 digest of the canonical boot-chain manifest.
    pub manifest_digest: String,
    /// Optional Ed25519 manifest signature.
    pub manifest_signature: Option<String>,
}

/// Coherent active-version and release-history snapshot.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ReleaseSnapshot {
    /// Active artifact versions.
    pub versions: Vec<VersionInfo>,
    /// Exact active release identities for each boot profile.
    pub active_groups: Vec<ActiveGroupInfo>,
    /// Retained release groups from the same atomic snapshot.
    pub groups: Vec<GroupInfo>,
}

/// Exact identity of one active boot-profile release.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ActiveGroupInfo {
    /// Boot-profile namespace.
    pub boot_profile: String,
    /// Operator-supplied release identifier.
    pub group_id: String,
    /// Process-local version identifier shared by group members.
    pub version_id: u64,
    /// SHA-256 digest binding the exact active manifest.
    pub manifest_digest: String,
}

/// Request for core-owned verification of one retained release.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VerifyGroupRequest {
    /// Boot-profile namespace.
    pub boot_profile: String,
    /// Operator-supplied release identifier.
    pub group_id: String,
    /// SHA-256 digest binding the exact release snapshot.
    pub manifest_digest: String,
    /// Logical artifacts to verify from that release in one bounded batch.
    pub files: Vec<String>,
}

/// Result of capability-confined server-side artifact verification.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct VerifyGroupResponse {
    /// Whether every artifact still matches its retained release manifest.
    pub verified: bool,
}

/// One logical-to-physical artifact mapping in a deployment request.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DeployFile {
    /// Logical name requested by boot clients.
    pub name: String,
    /// Existing regular file beneath Tempest's configured root.
    pub path: String,
}

/// Release cutover behavior.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CutoverPolicy {
    /// Wait for transfer and boot-session pins on the outgoing release.
    DrainAll,
    /// Preserve existing boot sessions while new sessions use the new release.
    PreserveSessions,
}

/// Request to prepare and activate a coordinated release.
#[derive(Debug, Clone, Serialize)]
pub struct DeployRequest {
    /// Target boot profile; `None` selects Tempest's `default` profile.
    pub boot_profile: Option<String>,
    /// Operator-supplied release identifier.
    pub group_id: String,
    /// Existing server-local artifact mappings.
    pub files: Vec<DeployFile>,
    /// Bounded drain wait requested from the server.
    pub drain_timeout_ms: Option<u64>,
    /// Cutover behavior.
    pub cutover_policy: CutoverPolicy,
}

/// Request to reactivate a historical release.
#[derive(Debug, Clone, Serialize)]
pub struct RollbackRequest {
    /// Target boot profile; `None` selects `default`.
    pub boot_profile: Option<String>,
    /// Historical group to reactivate.
    pub group_id: String,
    /// Optional manifest digest binding the rollback target.
    pub manifest_digest: Option<String>,
    /// Optional group that must still be active when rollback is applied.
    pub expected_active_group: Option<String>,
    /// Optional manifest digest binding the expected active release.
    pub expected_active_manifest_digest: Option<String>,
}

/// Request to remove an active release from new resolution.
#[derive(Debug, Clone, Serialize)]
pub struct WithdrawRequest {
    /// Target boot profile; `None` selects `default`.
    pub boot_profile: Option<String>,
    /// Group expected to be active. Tempest rejects stale identities.
    pub group_id: String,
    /// Optional manifest digest binding the expected active release.
    pub manifest_digest: Option<String>,
}

/// Request to register or advance a client boot epoch.
#[derive(Debug, Clone, Serialize)]
pub struct RegisterSessionRequest {
    /// Source IP from which Tempest will receive TFTP and HTTP requests.
    pub client_ip: IpAddr,
    /// Optional provisioning trace identifier.
    pub trace_id: Option<String>,
    /// Boot profile assigned to the client.
    pub boot_profile: Option<String>,
    /// Optional inventory MAC address.
    pub client_mac: Option<String>,
    /// Optional inventory serial number.
    pub serial: Option<String>,
    /// Session lifetime in seconds; Tempest caps this value.
    pub ttl_seconds: Option<u64>,
    /// Begin a new boot epoch instead of modifying an existing pinned attempt.
    pub new_epoch: bool,
    /// Require an active managed release instead of a direct-root session.
    pub require_managed: bool,
}

/// Proof that identifies the exact boot session to revoke.
#[derive(Clone, Serialize)]
pub struct RevokeSessionRequest {
    /// Artifact bearer token returned by registration. Never log this value.
    pub artifact_token: String,
}

impl fmt::Debug for RevokeSessionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RevokeSessionRequest")
            .field("artifact_token", &"[REDACTED]")
            .finish()
    }
}

trait ValidateRequest {
    fn validate(&self) -> Result<(), ControlError>;
}

fn invalid_request(message: &str) -> ControlError {
    ControlError::InvalidRequest(message.into())
}

fn valid_identifier(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_logical_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
        && Path::new(value)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn validate_string_budget<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> Result<(), ControlError> {
    let bytes = values.into_iter().try_fold(0usize, |total, value| {
        total
            .checked_add(value.len())
            .ok_or(ControlError::RequestTooLarge {
                limit: MAX_REQUEST_BODY_BYTES,
            })
    })?;
    if bytes > MAX_REQUEST_BODY_BYTES {
        return Err(ControlError::RequestTooLarge {
            limit: MAX_REQUEST_BODY_BYTES,
        });
    }
    Ok(())
}

impl ValidateRequest for VerifyGroupRequest {
    fn validate(&self) -> Result<(), ControlError> {
        if !valid_identifier(&self.boot_profile, 64)
            || !valid_identifier(&self.group_id, 128)
            || !valid_digest(&self.manifest_digest)
            || self.files.is_empty()
            || self.files.len() > 100
        {
            return Err(invalid_request("invalid retained-release identity"));
        }
        let mut unique = HashSet::with_capacity(self.files.len());
        if self
            .files
            .iter()
            .any(|file| !valid_logical_name(file) || !unique.insert(file.as_str()))
        {
            return Err(invalid_request("invalid retained-release identity"));
        }
        validate_string_budget(
            [&self.boot_profile, &self.group_id, &self.manifest_digest]
                .into_iter()
                .map(String::as_str)
                .chain(self.files.iter().map(String::as_str)),
        )
    }
}

impl ValidateRequest for DeployRequest {
    fn validate(&self) -> Result<(), ControlError> {
        let profile = self.boot_profile.as_deref().unwrap_or("default");
        if !valid_identifier(profile, 64)
            || !valid_identifier(&self.group_id, 128)
            || self.files.is_empty()
            || self.files.len() > 100
        {
            return Err(invalid_request("invalid deployment request"));
        }
        let mut unique = HashSet::with_capacity(self.files.len());
        if self.files.iter().any(|file| {
            !valid_logical_name(&file.name)
                || file.path.is_empty()
                || file.path.contains('\0')
                || !unique.insert(file.name.as_str())
        }) {
            return Err(invalid_request("invalid deployment request"));
        }
        validate_string_budget(
            [profile, self.group_id.as_str()].into_iter().chain(
                self.files
                    .iter()
                    .flat_map(|file| [file.name.as_str(), file.path.as_str()]),
            ),
        )
    }
}

impl ValidateRequest for RollbackRequest {
    fn validate(&self) -> Result<(), ControlError> {
        let profile = self.boot_profile.as_deref().unwrap_or("default");
        if !valid_identifier(profile, 64)
            || !valid_identifier(&self.group_id, 128)
            || self
                .manifest_digest
                .as_deref()
                .is_some_and(|digest| !valid_digest(digest))
            || self
                .expected_active_group
                .as_deref()
                .is_some_and(|group| !valid_identifier(group, 128))
            || self
                .expected_active_manifest_digest
                .as_deref()
                .is_some_and(|digest| !valid_digest(digest))
            || (self.expected_active_group.is_none()
                && self.expected_active_manifest_digest.is_some())
        {
            return Err(invalid_request("invalid rollback identity"));
        }
        validate_string_budget(
            [
                Some(profile),
                Some(self.group_id.as_str()),
                self.manifest_digest.as_deref(),
                self.expected_active_group.as_deref(),
                self.expected_active_manifest_digest.as_deref(),
            ]
            .into_iter()
            .flatten(),
        )
    }
}

impl ValidateRequest for WithdrawRequest {
    fn validate(&self) -> Result<(), ControlError> {
        let profile = self.boot_profile.as_deref().unwrap_or("default");
        if !valid_identifier(profile, 64)
            || !valid_identifier(&self.group_id, 128)
            || self
                .manifest_digest
                .as_deref()
                .is_some_and(|digest| !valid_digest(digest))
        {
            return Err(invalid_request("invalid withdrawal identity"));
        }
        validate_string_budget(
            [
                Some(profile),
                Some(self.group_id.as_str()),
                self.manifest_digest.as_deref(),
            ]
            .into_iter()
            .flatten(),
        )
    }
}

impl ValidateRequest for RevokeSessionRequest {
    fn validate(&self) -> Result<(), ControlError> {
        if self.artifact_token.len() != 64
            || !self
                .artifact_token
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid_request("invalid artifact token"));
        }
        Ok(())
    }
}

impl ValidateRequest for RegisterSessionRequest {
    fn validate(&self) -> Result<(), ControlError> {
        let profile = self.boot_profile.as_deref().unwrap_or("default");
        let valid_trace = self.trace_id.as_deref().is_none_or(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
        let valid_mac = self.client_mac.as_deref().is_none_or(|value| {
            value.len() <= 32
                && value
                    .bytes()
                    .filter(|byte| !matches!(byte, b':' | b'-'))
                    .count()
                    == 12
                && value
                    .bytes()
                    .filter(|byte| !matches!(byte, b':' | b'-'))
                    .all(|byte| byte.is_ascii_hexdigit())
        });
        let valid_serial = self.serial.as_deref().is_none_or(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
                })
        });
        if !valid_identifier(profile, 64)
            || !valid_trace
            || !valid_mac
            || !valid_serial
            || (profile == "default"
                && self.trace_id.is_none()
                && self.client_mac.is_none()
                && self.serial.is_none())
        {
            return Err(invalid_request("invalid boot-session identity"));
        }
        validate_string_budget(
            [
                Some(profile),
                self.trace_id.as_deref(),
                self.client_mac.as_deref(),
                self.serial.as_deref(),
            ]
            .into_iter()
            .flatten(),
        )
    }
}

fn rollback_path(request: &RollbackRequest) -> &'static str {
    if request.manifest_digest.is_some() || request.expected_active_manifest_digest.is_some() {
        "api/v2/versions/rollback"
    } else {
        "api/v1/versions/rollback"
    }
}

fn withdraw_path(request: &WithdrawRequest) -> &'static str {
    if request.manifest_digest.is_some() {
        "api/v2/versions/withdraw"
    } else {
        "api/v1/versions/withdraw"
    }
}

/// One-time HTTP artifact credential returned by session registration.
#[derive(Clone, Deserialize, PartialEq, Eq)]
pub struct RegisterSessionResponse {
    /// Bearer token shown only in this response.
    pub artifact_token: String,
    /// Profile selected by the server.
    pub boot_profile: String,
    /// Manifest pinned by the session, absent for unmanaged sessions.
    pub manifest_digest: Option<String>,
    /// RFC 3339 session expiration timestamp.
    pub expires_at: String,
    /// Provisioning generation assigned to the session.
    pub boot_epoch: u64,
}

impl fmt::Debug for RegisterSessionResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegisterSessionResponse")
            .field("artifact_token", &"[REDACTED]")
            .field("boot_profile", &self.boot_profile)
            .field("manifest_digest", &self.manifest_digest)
            .field("expires_at", &self.expires_at)
            .field("boot_epoch", &self.boot_epoch)
            .finish()
    }
}

/// Timeout-bounded client for one Tempest control endpoint.
pub struct ControlClient {
    base_url: Url,
    api_key: Option<String>,
    client: reqwest::Client,
    request_timeout: Duration,
    deployment_timeout: Duration,
}

/// Builder for secure transport and per-operation timeout policy.
pub struct ControlClientBuilder {
    base_url: String,
    api_key: Option<String>,
    request_timeout: Duration,
    deployment_timeout: Duration,
    allow_insecure_http: bool,
}

impl ControlClientBuilder {
    /// Allows remote plaintext HTTP. This is intentionally explicit and unsafe.
    pub fn dangerously_allow_insecure_http(mut self, allow: bool) -> Self {
        self.allow_insecure_http = allow;
        self
    }

    /// Sets the timeout for ordinary control operations.
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Sets the timeout for deployment and release-integrity operations.
    pub fn deployment_timeout(mut self, timeout: Duration) -> Self {
        self.deployment_timeout = timeout;
        self
    }

    /// Builds the validated client.
    pub fn build(self) -> Result<ControlClient, ControlError> {
        let mut base_url = Url::parse(&self.base_url)
            .map_err(|error| ControlError::InvalidUrl(error.to_string()))?;
        if !base_url.username().is_empty() || base_url.password().is_some() {
            return Err(ControlError::InvalidUrl(
                "URL userinfo is forbidden".to_string(),
            ));
        }
        if !matches!(base_url.scheme(), "http" | "https") {
            return Err(ControlError::InvalidUrl(format!(
                "unsupported scheme {}",
                base_url.scheme()
            )));
        }
        let numeric_loopback = base_url
            .host_str()
            .and_then(|host| host.parse::<IpAddr>().ok())
            .is_some_and(|address| address.is_loopback());
        if base_url.scheme() == "http" && !numeric_loopback && !self.allow_insecure_http {
            return Err(ControlError::InvalidUrl(
                "remote Tempest endpoints require HTTPS".to_string(),
            ));
        }
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        base_url.set_query(None);
        base_url.set_fragment(None);
        let mut client = reqwest::Client::builder()
            .connect_timeout(self.request_timeout)
            .redirect(reqwest::redirect::Policy::none());
        if numeric_loopback {
            client = client.no_proxy();
        }
        let client = client.build()?;
        Ok(ControlClient {
            base_url,
            api_key: self.api_key,
            client,
            request_timeout: self.request_timeout,
            deployment_timeout: self.deployment_timeout,
        })
    }
}

impl ControlClient {
    /// Construct a client for an HTTP or HTTPS Tempest base URL.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::InvalidUrl`] for invalid/non-HTTP URLs and
    /// [`ControlError::Transport`] when the bounded HTTP client cannot be built.
    pub fn new(base_url: &str, api_key: Option<String>) -> Result<Self, ControlError> {
        Self::builder(base_url, api_key).build()
    }

    /// Starts a client builder with secure transport defaults.
    pub fn builder(base_url: &str, api_key: Option<String>) -> ControlClientBuilder {
        ControlClientBuilder {
            base_url: base_url.to_string(),
            api_key,
            request_timeout: REQUEST_TIMEOUT,
            deployment_timeout: DEPLOYMENT_TIMEOUT,
            allow_insecure_http: false,
        }
    }

    /// List active artifact versions.
    pub async fn list_versions(&self) -> Result<Page<VersionInfo>, ControlError> {
        self.list_versions_page(None, 50).await
    }

    /// Lists a bounded page of active artifact versions.
    pub async fn list_versions_page(
        &self,
        cursor: Option<&str>,
        limit: u16,
    ) -> Result<Page<VersionInfo>, ControlError> {
        let path = page_path("api/v1/versions", cursor, limit);
        self.request_json(Method::GET, &path, Option::<&()>::None)
            .await
    }

    /// List version-group history and manifest identities.
    pub async fn list_groups(&self) -> Result<Page<GroupInfo>, ControlError> {
        self.list_groups_page(None, 50).await
    }

    /// Lists a bounded page of release-group history.
    pub async fn list_groups_page(
        &self,
        cursor: Option<&str>,
        limit: u16,
    ) -> Result<Page<GroupInfo>, ControlError> {
        let path = page_path("api/v1/versions/groups", cursor, limit);
        self.request_json(Method::GET, &path, Option::<&()>::None)
            .await
    }

    /// Fetch active versions and retained groups from one coherent snapshot.
    pub async fn release_snapshot(&self) -> Result<ReleaseSnapshot, ControlError> {
        self.request_json_with_timeout(
            Method::GET,
            "api/v1/versions/snapshot",
            Option::<&()>::None,
            self.deployment_timeout,
        )
        .await
    }

    /// Ask Tempest core to rehash one release through its capability root.
    pub async fn verify_group(
        &self,
        request: &VerifyGroupRequest,
    ) -> Result<VerifyGroupResponse, ControlError> {
        request.validate()?;
        self.request_json_with_timeout(
            Method::POST,
            "api/v1/versions/verify",
            Some(request),
            self.deployment_timeout,
        )
        .await
    }

    /// Inspect one deletion target without reserving it or changing state.
    pub async fn preview_delete(
        &self,
        request: &PreviewDeleteRequest,
    ) -> Result<DeletePreview, ControlError> {
        request.target.validate()?;
        self.request_json_with_timeout(
            Method::POST,
            "api/v2/delete/preview",
            Some(request),
            self.deployment_timeout,
        )
        .await
    }

    /// Confirm an exact preview identity; core rechecks blockers at commit.
    /// Never retry a conflict with a newly fetched identity without user confirmation.
    pub async fn confirm_delete(
        &self,
        request: &ConfirmDeleteRequest,
    ) -> Result<DeleteResult, ControlError> {
        request.validate()?;
        self.request_json_with_timeout(
            Method::POST,
            "api/v2/delete/confirm",
            Some(request),
            self.deployment_timeout,
        )
        .await
    }

    /// Prepare and activate a release.
    pub async fn deploy(&self, request: &DeployRequest) -> Result<GroupInfo, ControlError> {
        request.validate()?;
        self.request_json_with_timeout(
            Method::POST,
            "api/v1/versions/switch",
            Some(request),
            self.deployment_timeout,
        )
        .await
    }

    /// Reactivate a historical release.
    pub async fn rollback(&self, request: &RollbackRequest) -> Result<(), ControlError> {
        request.validate()?;
        self.request_empty_with_timeout(
            Method::POST,
            rollback_path(request),
            request,
            self.deployment_timeout,
        )
        .await
    }

    /// Withdraw the matching active release.
    pub async fn withdraw(&self, request: &WithdrawRequest) -> Result<(), ControlError> {
        request.validate()?;
        self.request_empty_with_timeout(
            Method::POST,
            withdraw_path(request),
            request,
            self.deployment_timeout,
        )
        .await
    }

    /// Register a client boot session.
    pub async fn register_session(
        &self,
        request: &RegisterSessionRequest,
    ) -> Result<RegisterSessionResponse, ControlError> {
        request.validate()?;
        self.request_json(Method::POST, "api/v1/sessions", Some(request))
            .await
    }

    /// Revoke only the session whose artifact token still matches.
    pub async fn revoke_session(
        &self,
        client_ip: IpAddr,
        request: &RevokeSessionRequest,
    ) -> Result<(), ControlError> {
        request.validate()?;
        self.request_empty_with_timeout(
            Method::DELETE,
            &format!("api/v1/sessions/{client_ip}"),
            request,
            self.request_timeout,
        )
        .await
    }

    async fn request_json<T, B>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T, ControlError>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        self.request_json_with_timeout(method, path, body, self.request_timeout)
            .await
    }

    async fn request_json_with_timeout<T, B>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        timeout: Duration,
    ) -> Result<T, ControlError>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let response = self.send(method, path, body, timeout).await?;
        let body = read_body_limited(response, MAX_JSON_BODY_BYTES).await?;
        Ok(serde_json::from_slice(&body)?)
    }

    async fn request_empty_with_timeout<B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        body: &B,
        timeout: Duration,
    ) -> Result<(), ControlError> {
        let response = self.send(method, path, Some(body), timeout).await?;
        let _ = read_body_limited(response, MAX_ERROR_BODY_BYTES).await?;
        Ok(())
    }

    async fn send<B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        timeout: Duration,
    ) -> Result<reqwest::Response, ControlError> {
        let url = self
            .base_url
            .join(path)
            .map_err(|error| ControlError::InvalidUrl(error.to_string()))?;
        let mut request = self.client.request(method, url).timeout(timeout);
        if let Some(api_key) = self.api_key.as_deref() {
            request = request.header("x-api-key", api_key);
        }
        if let Some(body) = body {
            let body = serde_json::to_vec(body)
                .map_err(|error| ControlError::InvalidRequest(error.to_string()))?;
            if body.len() > MAX_REQUEST_BODY_BYTES {
                return Err(ControlError::RequestTooLarge {
                    limit: MAX_REQUEST_BODY_BYTES,
                });
            }
            request = request.header(CONTENT_TYPE, "application/json").body(body);
        }
        let response = request.send().await?;
        if response.status().is_success() {
            return Ok(response);
        }
        let status = response.status();
        let bounded = read_body_prefix(response, MAX_ERROR_BODY_BYTES).await?;
        Err(ControlError::Api {
            status,
            message: String::from_utf8_lossy(&bounded).into_owned(),
        })
    }
}

fn page_path(base: &str, cursor: Option<&str>, limit: u16) -> String {
    let limit = limit.clamp(1, 100);
    let mut query_url =
        Url::parse("http://localhost/").expect("the static query URL must remain valid");
    {
        let mut query = query_url.query_pairs_mut();
        if let Some(cursor) = cursor {
            query.append_pair("cursor", cursor);
        }
        query.append_pair("limit", &limit.to_string());
    }
    format!(
        "{base}?{}",
        query_url
            .query()
            .expect("the limit parameter always creates a query")
    )
}

async fn read_body_limited(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, ControlError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(ControlError::ResponseTooLarge { limit });
    }
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or(0)
            .min(limit),
    );
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err(ControlError::ResponseTooLarge { limit });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn read_body_prefix(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, reqwest::Error> {
    let mut body = Vec::with_capacity(limit);
    while body.len() < limit {
        let Some(chunk) = response.chunk().await? else {
            break;
        };
        let take = chunk.len().min(limit - body.len());
        body.extend_from_slice(&chunk[..take]);
        if take < chunk.len() {
            break;
        }
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn rejects_non_http_base_url() {
        assert!(ControlClient::new("file:///tmp/tempest", None).is_err());
    }

    #[test]
    fn page_path_encodes_opaque_cursor_as_one_parameter() {
        let path = page_path("api/v1/versions", Some("next&limit=100#fragment=value"), 25);
        let url = Url::parse(&format!("http://localhost/{path}")).unwrap();
        let pairs = url.query_pairs().collect::<Vec<_>>();

        assert_eq!(
            pairs,
            vec![
                ("cursor".into(), "next&limit=100#fragment=value".into()),
                ("limit".into(), "25".into()),
            ]
        );
    }

    #[test]
    fn session_response_debug_redacts_artifact_token() {
        let response = RegisterSessionResponse {
            artifact_token: "sensitive-artifact-token".into(),
            boot_profile: "test".into(),
            manifest_digest: None,
            expires_at: "2026-07-23T00:00:00Z".into(),
            boot_epoch: 7,
        };
        let debug = format!("{response:?}");

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&response.artifact_token));
    }

    #[test]
    fn revoke_session_proof_is_bounded_and_redacted() {
        let request = RevokeSessionRequest {
            artifact_token: "a".repeat(64),
        };
        assert!(request.validate().is_ok());
        assert!(!format!("{request:?}").contains(&request.artifact_token));
        for invalid in ["", "short", &"z".repeat(64), &"a".repeat(65)] {
            assert!(
                RevokeSessionRequest {
                    artifact_token: invalid.into()
                }
                .validate()
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn list_versions_uses_versioned_path_and_api_key() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let server_requests = requests.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 4096];
            let length = stream.read(&mut buffer).await.unwrap();
            let request = String::from_utf8_lossy(&buffer[..length]);
            assert!(request.starts_with("GET /api/v1/versions?limit=50 HTTP/1.1"));
            assert!(request.to_ascii_lowercase().contains("x-api-key: test-key"));
            server_requests.fetch_add(1, Ordering::SeqCst);
            let body = r#"{"items":[],"next_cursor":null}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let client =
            ControlClient::new(&format!("http://{address}"), Some("test-key".into())).unwrap();

        assert!(client.list_versions().await.unwrap().items.is_empty());
        server.await.unwrap();
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn loopback_http_ignores_system_proxy() {
        if let Some(target) = std::env::var_os("TEMPEST_PROXY_TEST_TARGET") {
            let client =
                ControlClient::new(target.to_str().unwrap(), Some("test-key".into())).unwrap();
            assert!(client.list_versions().await.unwrap().items.is_empty());
            return;
        }

        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let target_server = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut request = [0u8; 2048];
            let length = stream.read(&mut request).await.unwrap();
            assert!(
                String::from_utf8_lossy(&request[..length])
                    .starts_with("GET /api/v1/versions?limit=50 HTTP/1.1")
            );
            let body = r#"{"items":[],"next_cursor":null}"#;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let proxy_server = tokio::spawn(async move { proxy.accept().await });
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::loopback_http_ignores_system_proxy",
                    "--nocapture",
                ])
                .env(
                    "TEMPEST_PROXY_TEST_TARGET",
                    format!("http://{target_address}"),
                )
                .env("HTTP_PROXY", format!("http://{proxy_address}"))
                .env("http_proxy", format!("http://{proxy_address}"))
                .env_remove("NO_PROXY")
                .env_remove("no_proxy")
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        assert!(
            output.status.success(),
            "child test failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        tokio::time::timeout(Duration::from_secs(30), target_server)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !proxy_server.is_finished(),
            "loopback request reached the proxy"
        );
        proxy_server.abort();
        assert!(proxy_server.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn integrity_methods_use_coherent_snapshot_and_verify_paths() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 4096];
            let length = stream.read(&mut buffer).await.unwrap();
            let request = String::from_utf8_lossy(&buffer[..length]);
            assert!(request.starts_with("GET /api/v1/versions/snapshot HTTP/1.1"));
            let body = r#"{"versions":[],"active_groups":[],"groups":[]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();

            let (mut stream, _) = listener.accept().await.unwrap();
            let length = stream.read(&mut buffer).await.unwrap();
            let request = String::from_utf8_lossy(&buffer[..length]);
            assert!(request.starts_with("POST /api/v1/versions/verify HTTP/1.1"));
            assert!(request.contains("\"boot_profile\":\"default\""));
            assert!(request.contains("\"group_id\":\"release-1\""));
            assert!(request.contains(&format!("\"manifest_digest\":\"{}\"", "a".repeat(64))));
            assert!(request.contains("\"files\":[\"kernel\"]"));
            let body = r#"{"verified":true}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let client = ControlClient::new(&format!("http://{address}"), None).unwrap();

        let snapshot = client.release_snapshot().await.unwrap();
        assert!(snapshot.versions.is_empty());
        assert!(snapshot.active_groups.is_empty());
        assert!(snapshot.groups.is_empty());
        assert!(
            client
                .verify_group(&VerifyGroupRequest {
                    boot_profile: "default".into(),
                    group_id: "release-1".into(),
                    manifest_digest: "a".repeat(64),
                    files: vec!["kernel".into()],
                })
                .await
                .unwrap()
                .verified
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_oversized_success_body_from_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _request_len = stream.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                MAX_JSON_BODY_BYTES + 1
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let client = ControlClient::new(&format!("http://{address}"), None).unwrap();

        assert!(matches!(
            client.list_versions().await,
            Err(ControlError::ResponseTooLarge {
                limit: MAX_JSON_BODY_BYTES
            })
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn error_message_is_truncated_before_buffering_the_whole_body() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _request_len = stream.read(&mut request).await.unwrap();
            let body = "x".repeat(MAX_ERROR_BODY_BYTES * 2);
            let response = format!(
                "HTTP/1.1 400 Bad Request\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let client = ControlClient::new(&format!("http://{address}"), None).unwrap();

        let error = client
            .request_empty_with_timeout(
                Method::POST,
                "api/v1/sessions",
                &(),
                client.request_timeout,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ControlError::Api { message, .. } if message.len() == MAX_ERROR_BODY_BYTES
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_success_json_returns_decode_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _request_len = stream.read(&mut request).await.unwrap();
            let body = "not-json";
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let client = ControlClient::new(&format!("http://{address}"), None).unwrap();

        assert!(matches!(
            client.list_versions().await,
            Err(ControlError::Decode(_))
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn redirects_are_returned_as_api_errors() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _request_len = stream.read(&mut request).await.unwrap();
            let body = "redirect refused";
            let response = format!(
                "HTTP/1.1 302 Found\r\nlocation: http://127.0.0.1:9/credential-leak\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let client = ControlClient::new(
            &format!("http://{address}"),
            Some("must-not-be-forwarded".into()),
        )
        .unwrap();

        assert!(matches!(
            client.list_versions().await,
            Err(ControlError::Api {
                status: StatusCode::FOUND,
                message,
            }) if message == "redirect refused"
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn integrity_operations_use_the_long_operation_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for body in [
                Some(r#"{"versions":[],"active_groups":[],"groups":[]}"#),
                Some(r#"{"verified":true}"#),
                None,
                None,
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 4096];
                let _request_len = stream.read(&mut request).await.unwrap();
                tokio::time::sleep(Duration::from_millis(60)).await;
                let body = body.unwrap_or_default();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let mut client = ControlClient::builder(&format!("http://{address}"), None)
            .request_timeout(Duration::from_secs(5))
            .deployment_timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        // The builder also uses request_timeout for TCP connection setup.
        // Keep transport tolerant of CI scheduling delays, then shorten only
        // the operation policy under test. The server's 60 ms delay still
        // exceeds this budget if an integrity method selects the wrong policy.
        client.request_timeout = Duration::from_millis(20);

        assert!(client.release_snapshot().await.unwrap().groups.is_empty());
        assert!(
            client
                .verify_group(&VerifyGroupRequest {
                    boot_profile: "default".into(),
                    group_id: "release-1".into(),
                    manifest_digest: "a".repeat(64),
                    files: vec!["kernel".into()],
                })
                .await
                .unwrap()
                .verified
        );
        client
            .rollback(&RollbackRequest {
                boot_profile: Some("default".into()),
                group_id: "release-1".into(),
                manifest_digest: Some("a".repeat(64)),
                expected_active_group: Some("release-2".into()),
                expected_active_manifest_digest: Some("b".repeat(64)),
            })
            .await
            .unwrap();
        client
            .withdraw(&WithdrawRequest {
                boot_profile: Some("default".into()),
                group_id: "release-1".into(),
                manifest_digest: Some("a".repeat(64)),
            })
            .await
            .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn invalid_and_oversized_requests_fail_before_transport() {
        let client = ControlClient::new("http://127.0.0.1:9", None).unwrap();
        for control in ['\t', '\x7f', '\u{85}', '\u{9f}'] {
            assert!(matches!(
                client
                    .verify_group(&VerifyGroupRequest {
                        boot_profile: "default".into(),
                        group_id: "release-1".into(),
                        manifest_digest: "a".repeat(64),
                        files: vec![format!("kernel{control}")],
                    })
                    .await,
                Err(ControlError::InvalidRequest(_))
            ));
        }
        assert!(matches!(
            client
                .verify_group(&VerifyGroupRequest {
                    boot_profile: "default".into(),
                    group_id: "release-1".into(),
                    manifest_digest: "a".repeat(64),
                    files: vec!["kernel".into(), "kernel".into()],
                })
                .await,
            Err(ControlError::InvalidRequest(_))
        ));
        assert!(matches!(
            VerifyGroupRequest {
                boot_profile: "default".into(),
                group_id: "release-1".into(),
                manifest_digest: "a".repeat(64),
                files: vec!["kernel".into(); 101],
            }
            .validate(),
            Err(ControlError::InvalidRequest(_))
        ));

        assert!(matches!(
            client
                .deploy(&DeployRequest {
                    boot_profile: Some("default".into()),
                    group_id: "release-1".into(),
                    files: vec![DeployFile {
                        name: "kernel".into(),
                        path: "\"".repeat(600_000),
                    }],
                    drain_timeout_ms: None,
                    cutover_policy: CutoverPolicy::PreserveSessions,
                })
                .await,
            Err(ControlError::RequestTooLarge {
                limit: MAX_REQUEST_BODY_BYTES
            })
        ));
    }

    #[tokio::test]
    async fn rollback_serializes_compare_active_identity() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 4096];
            let length = stream.read(&mut buffer).await.unwrap();
            let request = String::from_utf8_lossy(&buffer[..length]);
            assert!(request.starts_with("POST /api/v2/versions/rollback HTTP/1.1"));
            assert!(request.contains("\"group_id\":\"release-1\""));
            assert!(request.contains("\"expected_active_group\":\"release-2\""));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .await
                .unwrap();
        });
        let client = ControlClient::new(&format!("http://{address}"), None).unwrap();

        client
            .rollback(&RollbackRequest {
                boot_profile: Some("default".into()),
                group_id: "release-1".into(),
                manifest_digest: Some("a".repeat(64)),
                expected_active_group: Some("release-2".into()),
                expected_active_manifest_digest: Some("b".repeat(64)),
            })
            .await
            .unwrap();
        server.await.unwrap();
    }

    #[test]
    fn digest_identity_selects_fail_closed_v2_mutation_paths() {
        let rollback = RollbackRequest {
            boot_profile: None,
            group_id: "release-1".into(),
            manifest_digest: Some("a".repeat(64)),
            expected_active_group: None,
            expected_active_manifest_digest: None,
        };
        assert_eq!(rollback_path(&rollback), "api/v2/versions/rollback");
        let legacy_rollback = RollbackRequest {
            manifest_digest: None,
            ..rollback
        };
        assert_eq!(rollback_path(&legacy_rollback), "api/v1/versions/rollback");

        let withdraw = WithdrawRequest {
            boot_profile: None,
            group_id: "release-1".into(),
            manifest_digest: Some("b".repeat(64)),
        };
        assert_eq!(withdraw_path(&withdraw), "api/v2/versions/withdraw");
    }
}
