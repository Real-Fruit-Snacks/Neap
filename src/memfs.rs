//! In-memory virtual filesystem for forensic-free SFTP operations.
//!
//! All files and directories live entirely in RAM — nothing touches disk.
//! This module is designed for use with the SFTP subsystem so that file
//! transfers leave no artifacts on the target host.

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

/// Metadata for an in-memory file or directory.
#[derive(Debug, Clone)]
pub struct MemMetadata {
    /// Size in bytes (0 for directories).
    pub size: u64,
    /// Unix-style permission mode bits.
    pub permissions: u32,
    /// Last-modified timestamp.
    pub modified: SystemTime,
    /// Whether this entry is a directory.
    #[allow(dead_code)]
    pub is_dir: bool,
}

/// An in-memory virtual filesystem.
///
/// Stores files as byte vectors and tracks directories and metadata in hash
/// maps. Thread-safe access is provided via [`SharedMemFs`].
pub struct MemFs {
    files: HashMap<PathBuf, Vec<u8>>,
    dirs: HashSet<PathBuf>,
    metadata: HashMap<PathBuf, MemMetadata>,
}

/// Thread-safe shared handle to a [`MemFs`].
pub type SharedMemFs = Arc<RwLock<MemFs>>;

/// Create a new [`SharedMemFs`] wrapped in an `Arc<RwLock>`.
pub fn new_shared() -> SharedMemFs {
    Arc::new(RwLock::new(MemFs::new()))
}

/// Root path for the in-memory filesystem.
fn root_path() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from("C:\\")
    } else {
        PathBuf::from("/")
    }
}

impl MemFs {
    /// Create an empty filesystem with only the root directory.
    pub fn new() -> Self {
        let root = root_path();
        let mut dirs = HashSet::new();
        dirs.insert(root.clone());

        let mut metadata = HashMap::new();
        metadata.insert(
            root,
            MemMetadata {
                size: 0,
                permissions: 0o755,
                modified: SystemTime::now(),
                is_dir: true,
            },
        );

        Self {
            files: HashMap::new(),
            dirs,
            metadata,
        }
    }

    /// Normalize a path by resolving `.` and `..` components and ensuring it
    /// is absolute.
    ///
    /// Relative paths are anchored to the filesystem root.
    pub fn normalize<P: AsRef<Path>>(&self, path: P) -> PathBuf {
        let path = path.as_ref();
        let root = root_path();

        // If relative, prepend root
        let working = if path.is_relative() {
            root.join(path)
        } else {
            path.to_path_buf()
        };

        let mut components = Vec::new();
        let mut root_len = 0usize;
        for component in working.components() {
            match component {
                Component::Prefix(_) | Component::RootDir => {
                    // On Windows a root path has both Prefix("C:") and
                    // RootDir; on Unix there is only RootDir. Keep all
                    // root-level components so the reassembled path is
                    // correct (e.g. "C:\" not "C:").
                    components.push(component);
                    root_len = components.len();
                }
                Component::CurDir => { /* skip */ }
                Component::ParentDir => {
                    // Pop last normal component, but never go above root
                    if components.len() > root_len {
                        components.pop();
                    }
                }
                Component::Normal(_) => {
                    components.push(component);
                }
            }
        }

        let result: PathBuf = components.iter().collect();
        if result.as_os_str().is_empty() {
            root
        } else {
            result
        }
    }

    /// Check whether a path exists (file or directory).
    pub fn exists<P: AsRef<Path>>(&self, path: P) -> bool {
        let path = self.normalize(path);
        self.files.contains_key(&path) || self.dirs.contains(&path)
    }

    /// Check whether a path is a directory.
    pub fn is_dir<P: AsRef<Path>>(&self, path: P) -> bool {
        let path = self.normalize(path);
        self.dirs.contains(&path)
    }

    /// Get metadata for a path.
    pub fn stat<P: AsRef<Path>>(&self, path: P) -> io::Result<MemMetadata> {
        let path = self.normalize(path);
        self.metadata
            .get(&path)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "path not found"))
    }

    /// Create or overwrite a file with the given data.
    ///
    /// Parent directories must already exist. The file is created with
    /// permissions `0o644`.
    pub fn create_file<P: AsRef<Path>>(&mut self, path: P, data: Vec<u8>) -> io::Result<()> {
        let path = self.normalize(path);

        // Ensure parent exists
        if let Some(parent) = path.parent() {
            let parent = parent.to_path_buf();
            if !self.dirs.contains(&parent) {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "parent directory does not exist",
                ));
            }
        }

        let size = data.len() as u64;
        self.files.insert(path.clone(), data);
        // Remove from dirs if it was somehow a dir (overwrite semantics)
        self.dirs.remove(&path);
        self.metadata.insert(
            path,
            MemMetadata {
                size,
                permissions: 0o644,
                modified: SystemTime::now(),
                is_dir: false,
            },
        );
        Ok(())
    }

    /// Read the full contents of a file.
    #[allow(dead_code)]
    pub fn read_file<P: AsRef<Path>>(&self, path: P) -> io::Result<Vec<u8>> {
        let path = self.normalize(path);
        self.files
            .get(&path)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "file not found"))
    }

    /// Write data at a specific byte offset within an existing file.
    ///
    /// If the offset is beyond the current end, the file is extended with
    /// zero bytes. If the write extends past the current end, the file grows.
    pub fn write_at<P: AsRef<Path>>(
        &mut self,
        path: P,
        offset: u64,
        data: &[u8],
    ) -> io::Result<()> {
        let path = self.normalize(path);
        let file = self
            .files
            .get_mut(&path)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "file not found"))?;

        let offset = offset as usize;
        let needed = offset + data.len();
        if needed > file.len() {
            file.resize(needed, 0);
        }
        file[offset..offset + data.len()].copy_from_slice(data);

        // Update metadata
        if let Some(meta) = self.metadata.get_mut(&path) {
            meta.size = file.len() as u64;
            meta.modified = SystemTime::now();
        }

        Ok(())
    }

    /// Read a slice of bytes from a file starting at the given offset.
    ///
    /// Returns up to `len` bytes. If the offset is at or beyond the end of
    /// the file, an empty vector is returned.
    pub fn read_at<P: AsRef<Path>>(&self, path: P, offset: u64, len: u64) -> io::Result<Vec<u8>> {
        let path = self.normalize(path);
        let file = self
            .files
            .get(&path)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "file not found"))?;

        let offset = offset as usize;
        let len = len as usize;
        if offset >= file.len() {
            return Ok(Vec::new());
        }
        let end = std::cmp::min(offset + len, file.len());
        Ok(file[offset..end].to_vec())
    }

    /// Create a directory. Parent directories must already exist.
    ///
    /// The directory is created with permissions `0o755`.
    pub fn mkdir<P: AsRef<Path>>(&mut self, path: P) -> io::Result<()> {
        let path = self.normalize(path);

        if self.dirs.contains(&path) || self.files.contains_key(&path) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "path already exists",
            ));
        }

        // Ensure parent exists
        if let Some(parent) = path.parent() {
            let parent = parent.to_path_buf();
            if !self.dirs.contains(&parent) {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "parent directory does not exist",
                ));
            }
        }

        self.dirs.insert(path.clone());
        self.metadata.insert(
            path,
            MemMetadata {
                size: 0,
                permissions: 0o755,
                modified: SystemTime::now(),
                is_dir: true,
            },
        );
        Ok(())
    }

    /// Remove a file.
    pub fn remove_file<P: AsRef<Path>>(&mut self, path: P) -> io::Result<()> {
        let path = self.normalize(path);
        if self.files.remove(&path).is_none() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "file not found"));
        }
        self.metadata.remove(&path);
        Ok(())
    }

    /// Remove an empty directory.
    ///
    /// Fails if the directory is not empty.
    pub fn remove_dir<P: AsRef<Path>>(&mut self, path: P) -> io::Result<()> {
        let path = self.normalize(path);
        if !self.dirs.contains(&path) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "directory not found",
            ));
        }

        // Check if directory is empty
        let has_children = self
            .files
            .keys()
            .any(|p| p.parent() == Some(path.as_path()))
            || self
                .dirs
                .iter()
                .any(|p| p != &path && p.parent() == Some(path.as_path()));

        if has_children {
            return Err(io::Error::other("directory is not empty"));
        }

        self.dirs.remove(&path);
        self.metadata.remove(&path);
        Ok(())
    }

    /// Rename a file or directory.
    pub fn rename<P: AsRef<Path>>(&mut self, from: P, to: P) -> io::Result<()> {
        let from = self.normalize(from);
        let to = self.normalize(to);

        if let Some(data) = self.files.remove(&from) {
            let meta = self.metadata.remove(&from);
            self.files.insert(to.clone(), data);
            if let Some(mut meta) = meta {
                meta.modified = SystemTime::now();
                self.metadata.insert(to, meta);
            }
            Ok(())
        } else if self.dirs.contains(&from) {
            self.dirs.remove(&from);
            let meta = self.metadata.remove(&from);
            self.dirs.insert(to.clone());
            if let Some(mut meta) = meta {
                meta.modified = SystemTime::now();
                self.metadata.insert(to, meta);
            }
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "path not found"))
        }
    }

    /// List the entries in a directory.
    ///
    /// Returns a vector of `(name, metadata)` pairs for each direct child.
    pub fn list_dir<P: AsRef<Path>>(&self, path: P) -> io::Result<Vec<(String, MemMetadata)>> {
        let path = self.normalize(path);
        if !self.dirs.contains(&path) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "directory not found",
            ));
        }

        let mut entries = Vec::new();

        // Collect child files
        for file_path in self.files.keys() {
            if file_path.parent() == Some(path.as_path()) {
                if let Some(name) = file_path.file_name() {
                    if let Some(meta) = self.metadata.get(file_path) {
                        entries.push((name.to_string_lossy().to_string(), meta.clone()));
                    }
                }
            }
        }

        // Collect child directories
        for dir_path in &self.dirs {
            if dir_path != &path && dir_path.parent() == Some(path.as_path()) {
                if let Some(name) = dir_path.file_name() {
                    if let Some(meta) = self.metadata.get(dir_path) {
                        entries.push((name.to_string_lossy().to_string(), meta.clone()));
                    }
                }
            }
        }

        Ok(entries)
    }

    /// Set the permission bits on a file or directory.
    pub fn set_permissions<P: AsRef<Path>>(&mut self, path: P, perms: u32) -> io::Result<()> {
        let path = self.normalize(path);
        let meta = self
            .metadata
            .get_mut(&path)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "path not found"))?;
        meta.permissions = perms;
        meta.modified = SystemTime::now();
        Ok(())
    }
}

impl Default for MemFs {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        root_path()
    }

    #[test]
    fn test_create_and_read_file() {
        let mut fs = MemFs::new();
        let path = root().join("hello.txt");
        fs.create_file(&path, b"hello world".to_vec()).unwrap();
        let data = fs.read_file(&path).unwrap();
        assert_eq!(data, b"hello world");
    }

    #[test]
    fn test_write_at_extends_file() {
        let mut fs = MemFs::new();
        let path = root().join("data.bin");
        fs.create_file(&path, b"AAAA".to_vec()).unwrap();
        // Write past the current end
        fs.write_at(&path, 2, b"BBBBBB").unwrap();
        let data = fs.read_file(&path).unwrap();
        assert_eq!(data.len(), 8); // 2 + 6
        assert_eq!(&data[0..2], b"AA");
        assert_eq!(&data[2..8], b"BBBBBB");
    }

    #[test]
    fn test_write_at_beyond_end() {
        let mut fs = MemFs::new();
        let path = root().join("sparse.bin");
        fs.create_file(&path, b"AB".to_vec()).unwrap();
        // Write starting at offset 5 — gap should be zero-filled
        fs.write_at(&path, 5, b"CD").unwrap();
        let data = fs.read_file(&path).unwrap();
        assert_eq!(data.len(), 7);
        assert_eq!(&data[0..2], b"AB");
        assert_eq!(&data[2..5], &[0, 0, 0]);
        assert_eq!(&data[5..7], b"CD");
    }

    #[test]
    fn test_read_at() {
        let mut fs = MemFs::new();
        let path = root().join("slice.txt");
        fs.create_file(&path, b"abcdefgh".to_vec()).unwrap();
        let slice = fs.read_at(&path, 2, 4).unwrap();
        assert_eq!(slice, b"cdef");

        // Read past end should be clamped
        let slice = fs.read_at(&path, 6, 100).unwrap();
        assert_eq!(slice, b"gh");

        // Read at end returns empty
        let slice = fs.read_at(&path, 100, 5).unwrap();
        assert!(slice.is_empty());
    }

    #[test]
    fn test_mkdir_and_list() {
        let mut fs = MemFs::new();
        let dir = root().join("mydir");
        fs.mkdir(&dir).unwrap();
        assert!(fs.is_dir(&dir));

        let file = dir.join("file.txt");
        fs.create_file(&file, b"content".to_vec()).unwrap();

        let sub = dir.join("subdir");
        fs.mkdir(&sub).unwrap();

        let entries = fs.list_dir(&dir).unwrap();
        let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"file.txt"));
        assert!(names.contains(&"subdir"));
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_remove_file() {
        let mut fs = MemFs::new();
        let path = root().join("gone.txt");
        fs.create_file(&path, b"bye".to_vec()).unwrap();
        assert!(fs.exists(&path));
        fs.remove_file(&path).unwrap();
        assert!(!fs.exists(&path));
    }

    #[test]
    fn test_remove_nonempty_dir_fails() {
        let mut fs = MemFs::new();
        let dir = root().join("notempty");
        fs.mkdir(&dir).unwrap();
        let file = dir.join("child.txt");
        fs.create_file(&file, b"x".to_vec()).unwrap();
        let result = fs.remove_dir(&dir);
        assert!(result.is_err());
        // Directory should still exist
        assert!(fs.is_dir(&dir));
    }

    #[test]
    fn test_rename_file() {
        let mut fs = MemFs::new();
        let old = root().join("old.txt");
        let new = root().join("new.txt");
        fs.create_file(&old, b"data".to_vec()).unwrap();
        fs.rename(&old, &new).unwrap();
        assert!(!fs.exists(&old));
        assert_eq!(fs.read_file(&new).unwrap(), b"data");
    }

    #[test]
    fn test_normalize() {
        let fs = MemFs::new();
        let root = root();

        // Dot and double-dot resolution
        let normalized = fs.normalize(root.join("a").join("b").join("..").join("c"));
        assert_eq!(normalized, root.join("a").join("c"));

        // Current-dir is removed
        let normalized = fs.normalize(root.join(".").join("x"));
        assert_eq!(normalized, root.join("x"));

        // Cannot go above root
        let normalized = fs.normalize(root.join("..").join("..").join("foo"));
        assert_eq!(normalized, root.join("foo"));
    }

    #[test]
    fn test_stat_metadata() {
        let mut fs = MemFs::new();
        let path = root().join("meta.txt");
        fs.create_file(&path, b"12345".to_vec()).unwrap();

        let meta = fs.stat(&path).unwrap();
        assert_eq!(meta.size, 5);
        assert_eq!(meta.permissions, 0o644);
        assert!(!meta.is_dir);

        // Change permissions and verify
        fs.set_permissions(&path, 0o600).unwrap();
        let meta = fs.stat(&path).unwrap();
        assert_eq!(meta.permissions, 0o600);

        // Directories should report is_dir
        let dir = root().join("statdir");
        fs.mkdir(&dir).unwrap();
        let meta = fs.stat(&dir).unwrap();
        assert!(meta.is_dir);
        assert_eq!(meta.permissions, 0o755);
    }
}
