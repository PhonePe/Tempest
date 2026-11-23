// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Capability-confined artifact filesystem access.

use std::path::{Component, Path, PathBuf};

use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};

use crate::error::{ProtocolError, TempestError};

/// Regular artifact opened beneath the process-lifetime capability root.
pub(crate) struct OpenedArtifact {
    pub file: std::fs::File,
    pub path: PathBuf,
    pub metadata: std::fs::Metadata,
}

/// Joins a client-visible artifact name without consulting ambient filesystem state.
pub(crate) fn lexical_artifact_path(
    root: &Path,
    candidate: &Path,
) -> Result<PathBuf, TempestError> {
    Ok(root.join(strict_relative_artifact_path(candidate)?))
}

fn strict_relative_artifact_path(path: &Path) -> Result<PathBuf, TempestError> {
    normalize_relative_artifact_path(path, ParentDirPolicy::Reject)
}

#[derive(Clone, Copy)]
enum ParentDirPolicy {
    Reject,
    ResolveWithinRoot,
}

fn normalize_relative_artifact_path(
    path: &Path,
    parent_dir_policy: ParentDirPolicy,
) -> Result<PathBuf, TempestError> {
    if path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(TempestError::Protocol(ProtocolError::AccessViolation(
            "artifact path contains a null byte".to_string(),
        )));
    }
    let mut relative = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => relative.push(value),
            Component::CurDir => {}
            Component::ParentDir
                if matches!(parent_dir_policy, ParentDirPolicy::ResolveWithinRoot)
                    && relative.pop() => {}
            Component::ParentDir => {
                return Err(TempestError::Protocol(ProtocolError::AccessViolation(
                    "artifact path escapes the configured root".to_string(),
                )));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(TempestError::Protocol(ProtocolError::AccessViolation(
                    "artifact path contains a forbidden component".to_string(),
                )));
            }
        }
    }
    if relative.as_os_str().is_empty() {
        return Err(TempestError::Protocol(ProtocolError::AccessViolation(
            "artifact path is empty".to_string(),
        )));
    }
    Ok(relative)
}

/// An artifact root held open for the lifetime of a server instance.
pub(crate) struct ArtifactRoot {
    directory: Dir,
    configured_path: PathBuf,
    display_path: PathBuf,
}

impl ArtifactRoot {
    pub(crate) fn open(path: &Path) -> Result<Self, TempestError> {
        let configured_path = std::path::absolute(path).map_err(|error| {
            TempestError::Config(format!(
                "failed to make artifact root absolute {}: {error}",
                path.display()
            ))
        })?;
        let display_path = std::fs::canonicalize(path).map_err(|error| {
            TempestError::Config(format!(
                "failed to resolve artifact root {}: {error}",
                path.display()
            ))
        })?;
        let directory =
            Dir::open_ambient_dir(&display_path, ambient_authority()).map_err(|error| {
                TempestError::Config(format!(
                    "failed to open artifact root {}: {error}",
                    display_path.display()
                ))
            })?;
        Ok(Self {
            directory,
            configured_path,
            display_path,
        })
    }

    /// Opens one regular artifact without returning to ambient path lookup.
    pub(crate) fn open_read(
        &self,
        candidate: &Path,
    ) -> Result<(std::fs::File, PathBuf), TempestError> {
        let opened = self.open_read_with_metadata(candidate)?;
        Ok((opened.file, opened.path))
    }

    /// Opens and describes one artifact through a single capability operation.
    pub(crate) fn open_read_with_metadata(
        &self,
        candidate: &Path,
    ) -> Result<OpenedArtifact, TempestError> {
        let relative = self.relative_path(candidate)?;
        self.open_relative_with_metadata(relative)
    }

    /// Opens an operator-supplied release source after root-confined lexical normalization.
    pub(crate) fn open_release_source_with_metadata(
        &self,
        candidate: &Path,
    ) -> Result<OpenedArtifact, TempestError> {
        let candidate = self.candidate_beneath_root(candidate)?;
        let relative =
            normalize_relative_artifact_path(candidate, ParentDirPolicy::ResolveWithinRoot)?;
        self.open_relative_with_metadata(relative)
    }

    fn open_relative_with_metadata(
        &self,
        relative: PathBuf,
    ) -> Result<OpenedArtifact, TempestError> {
        let file = self
            .directory
            .open(&relative)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::NotFound => TempestError::Protocol(
                    ProtocolError::FileNotFound(relative.display().to_string()),
                ),
                std::io::ErrorKind::PermissionDenied => {
                    TempestError::Protocol(ProtocolError::AccessViolation(
                        "artifact path is not accessible beneath the configured root".to_string(),
                    ))
                }
                _ => TempestError::Io(error),
            })?;
        let file = file.into_std();
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(TempestError::Protocol(ProtocolError::AccessViolation(
                "artifact is not a regular file".to_string(),
            )));
        }
        Ok(OpenedArtifact {
            file,
            path: self.display_path.join(relative),
            metadata,
        })
    }

    /// Opens a regular file for confined, advisory deletion inspection.
    ///
    /// Deletion inspection uses a separate nonblocking open on Unix so a FIFO
    /// cannot consume a bounded preview worker while waiting for a writer.
    pub(crate) fn open_delete_inspection(
        &self,
        candidate: &Path,
    ) -> Result<OpenedArtifact, TempestError> {
        let relative = self.relative_path(candidate)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
        }
        #[cfg(not(unix))]
        return Err(TempestError::Config(
            "file deletion inspection requires Unix".into(),
        ));
        let file = self
            .directory
            .open_with(&relative, &options)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::NotFound => {
                    TempestError::Protocol(ProtocolError::FileNotFound("delete target".into()))
                }
                std::io::ErrorKind::PermissionDenied => TempestError::Protocol(
                    ProtocolError::AccessViolation("unconfined delete target".into()),
                ),
                _ => TempestError::Io(error),
            })?
            .into_std();
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(TempestError::Protocol(ProtocolError::AccessViolation(
                "delete target is not a regular file".into(),
            )));
        }
        Ok(OpenedArtifact {
            file,
            metadata,
            path: self.display_path.join(relative),
        })
    }

    /// Validates that a stored artifact name remains beneath this capability.
    pub(crate) fn validate_candidate(&self, candidate: &Path) -> Result<(), TempestError> {
        self.relative_path(candidate).map(|_| ())
    }

    /// Creates a private temporary file and returns capability-relative names.
    pub(crate) fn create_write_temp(
        &self,
        logical_name: &str,
        suffix: &str,
    ) -> Result<(std::fs::File, PathBuf, PathBuf), TempestError> {
        let final_relative = self.relative_path(Path::new(logical_name))?;
        if final_relative.components().count() > 10 {
            return Err(TempestError::Protocol(ProtocolError::AccessViolation(
                "directory depth limit exceeded".to_string(),
            )));
        }
        if let Some(parent) = final_relative.parent() {
            if !parent.as_os_str().is_empty() {
                self.directory.create_dir_all(parent)?;
            }
        }

        let mut temp_relative = final_relative.clone();
        let temp_name = final_relative
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                TempestError::Protocol(ProtocolError::AccessViolation(
                    "invalid write filename".to_string(),
                ))
            })?;
        temp_relative.set_file_name(format!(".{temp_name}.tempest.{suffix}"));

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        let file = self.directory.open_with(&temp_relative, &options)?;
        let std_file = file.into_std();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std_file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        Ok((std_file, temp_relative, final_relative))
    }

    /// Publishes a completed temp file without clobbering unless explicitly allowed.
    pub(crate) fn publish_write(
        &self,
        temp_relative: &Path,
        final_relative: &Path,
        allow_overwrite: bool,
    ) -> Result<(), TempestError> {
        if allow_overwrite {
            self.directory
                .rename(temp_relative, &self.directory, final_relative)?;
        } else {
            self.directory
                .hard_link(temp_relative, &self.directory, final_relative)?;
            self.directory.remove_file(temp_relative)?;
        }
        self.sync_parent(final_relative)?;
        Ok(())
    }

    pub(crate) fn remove_file(&self, relative: &Path) {
        let _ = self.directory.remove_file(relative);
    }

    fn sync_parent(&self, relative: &Path) -> Result<(), TempestError> {
        #[cfg(unix)]
        {
            // cap-std intentionally represents directories with O_PATH on
            // Linux. O_PATH is sufficient for confined path resolution but
            // fsync rejects it with EBADF, so capability-open the parent as a
            // readable file descriptor before establishing rename durability.
            let parent = relative
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            self.directory.open(parent)?.sync_all()?;
        }
        Ok(())
    }

    fn relative_path(&self, candidate: &Path) -> Result<PathBuf, TempestError> {
        strict_relative_artifact_path(self.candidate_beneath_root(candidate)?)
    }

    fn candidate_beneath_root<'a>(&self, candidate: &'a Path) -> Result<&'a Path, TempestError> {
        if candidate.is_absolute() {
            candidate
                .strip_prefix(&self.configured_path)
                .or_else(|_| candidate.strip_prefix(&self.display_path))
                .map_err(|_| {
                    TempestError::Protocol(ProtocolError::AccessViolation(
                        "artifact path escapes configured root".to_string(),
                    ))
                })
        } else {
            Ok(candidate)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn publish_without_overwrite_durably_installs_new_file() {
        let directory = tempfile::tempdir().unwrap();
        let root = ArtifactRoot::open(directory.path()).unwrap();
        let (mut temp, temp_path, final_path) = root.create_write_temp("artifact", "new").unwrap();
        temp.write_all(b"published").unwrap();
        temp.sync_all().unwrap();
        drop(temp);

        root.publish_write(&temp_path, &final_path, false).unwrap();
        assert_eq!(
            std::fs::read(directory.path().join("artifact")).unwrap(),
            b"published"
        );
        assert!(!directory.path().join(temp_path).exists());
    }

    #[test]
    fn publish_without_overwrite_preserves_existing_file() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("artifact"), b"original").unwrap();
        let root = ArtifactRoot::open(directory.path()).unwrap();
        let (mut temp, temp_path, final_path) =
            root.create_write_temp("artifact", "collision").unwrap();
        temp.write_all(b"replacement").unwrap();
        temp.sync_all().unwrap();
        drop(temp);

        assert!(root.publish_write(&temp_path, &final_path, false).is_err());
        assert_eq!(
            std::fs::read(directory.path().join("artifact")).unwrap(),
            b"original"
        );
        root.remove_file(&temp_path);
    }

    #[cfg(unix)]
    #[test]
    fn parent_symlink_cannot_escape_for_read_or_write() {
        use std::os::unix::fs::symlink;

        let root_directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), b"outside").unwrap();
        symlink(outside.path(), root_directory.path().join("escape")).unwrap();
        symlink(
            format!("{}/", outside.path().display()),
            root_directory.path().join("trailing-target"),
        )
        .unwrap();
        symlink(
            outside.path().join("secret"),
            root_directory.path().join("final-link"),
        )
        .unwrap();
        let root = ArtifactRoot::open(root_directory.path()).unwrap();

        assert!(root.directory.open_dir("escape/").is_err());
        assert!(root.directory.open_dir("trailing-target").is_err());
        assert!(matches!(
            root.open_read(Path::new("escape/secret")),
            Err(TempestError::Protocol(ProtocolError::AccessViolation(_)))
        ));
        assert!(matches!(
            root.open_read(Path::new("final-link")),
            Err(TempestError::Protocol(ProtocolError::AccessViolation(_)))
        ));
        assert!(
            root.create_write_temp("escape/new-artifact", "attempt")
                .is_err()
        );
        assert!(!outside.path().join("new-artifact").exists());
    }

    #[test]
    fn opens_absolute_paths_derived_from_the_configured_root() {
        let directory = tempfile::tempdir().unwrap();
        let candidate = directory.path().join("artifact");
        std::fs::write(&candidate, b"trusted").unwrap();
        let root = ArtifactRoot::open(directory.path()).unwrap();

        let (mut file, _) = root.open_read(&candidate).unwrap();
        let mut contents = String::new();
        std::io::Read::read_to_string(&mut file, &mut contents).unwrap();
        assert_eq!(contents, "trusted");
    }

    #[test]
    fn read_rejects_a_directory_as_a_non_regular_artifact() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("nested")).unwrap();
        let root = ArtifactRoot::open(directory.path()).unwrap();

        assert!(matches!(
            root.open_read(Path::new("nested")),
            Err(TempestError::Protocol(ProtocolError::AccessViolation(_)))
        ));
    }

    #[test]
    fn read_distinguishes_a_missing_confined_artifact() {
        let directory = tempfile::tempdir().unwrap();
        let root = ArtifactRoot::open(directory.path()).unwrap();

        assert!(matches!(
            root.open_read(Path::new("missing")),
            Err(TempestError::Protocol(ProtocolError::FileNotFound(_)))
        ));
    }

    #[test]
    fn read_rejects_an_absolute_path_outside_the_artifact_root() {
        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_artifact = outside.path().join("artifact");
        std::fs::write(&outside_artifact, b"outside").unwrap();
        let root = ArtifactRoot::open(directory.path()).unwrap();

        assert!(matches!(
            root.open_read(&outside_artifact),
            Err(TempestError::Protocol(ProtocolError::AccessViolation(_)))
        ));
    }

    #[test]
    fn release_source_accepts_parent_components_that_remain_inside_the_root() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("images")).unwrap();
        std::fs::write(directory.path().join("kernel"), b"kernel").unwrap();
        let root = ArtifactRoot::open(directory.path()).unwrap();
        let candidate = directory.path().join("images/../kernel");

        let opened = root.open_release_source_with_metadata(&candidate).unwrap();
        assert_eq!(
            opened.path,
            std::fs::canonicalize(directory.path())
                .unwrap()
                .join("kernel")
        );
        assert!(root.open_read(&candidate).is_err());
    }

    #[test]
    fn release_source_rejects_parent_components_that_escape_the_root() {
        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("artifact"), b"outside").unwrap();
        let root = ArtifactRoot::open(directory.path()).unwrap();

        assert!(matches!(
            root.open_release_source_with_metadata(Path::new("../artifact")),
            Err(TempestError::Protocol(ProtocolError::AccessViolation(_)))
        ));
    }

    #[test]
    fn lexical_path_rejects_escape_without_requiring_the_file_to_exist() {
        let root = Path::new("/tftpboot");
        assert_eq!(
            lexical_artifact_path(root, Path::new("./images/kernel")).unwrap(),
            PathBuf::from("/tftpboot/images/kernel")
        );
        assert!(lexical_artifact_path(root, Path::new("../etc/passwd")).is_err());
        assert!(lexical_artifact_path(root, Path::new("/etc/passwd")).is_err());
        assert!(lexical_artifact_path(root, Path::new("")).is_err());
    }
}
