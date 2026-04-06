//! SFTP subsystem handler backed by real filesystem operations.
//!
//! Implements `russh_sftp::server::Handler` with full read/write access —
//! this is a pentest tool, so no sandboxing is applied.

use std::collections::HashMap;
use std::path::PathBuf;

use log::{error, info};
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Packet, Status, StatusCode, Version,
};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

/// State for a single SFTP session.
pub struct SftpHandler {
    /// Protocol version negotiated with the client.
    version: Option<u32>,
    /// Monotonically increasing counter for generating unique handle IDs.
    next_handle: u64,
    /// Open file handles: handle-string -> tokio::fs::File.
    file_handles: HashMap<String, tokio::fs::File>,
    /// Open directory handles: handle-string -> (path, already-read flag).
    /// The bool tracks whether we have already sent the listing (readdir
    /// must return Eof on the second call).
    dir_handles: HashMap<String, (PathBuf, bool)>,
}

impl SftpHandler {
    pub fn new() -> Self {
        Self {
            version: None,
            next_handle: 0,
            file_handles: HashMap::new(),
            dir_handles: HashMap::new(),
        }
    }

    /// Allocate a new unique handle string.
    fn alloc_handle(&mut self) -> String {
        let h = self.next_handle;
        self.next_handle += 1;
        format!("h{}", h)
    }
}

/// Convert `std::io::Error` to an SFTP `StatusCode`.
fn io_to_status(e: &std::io::Error) -> StatusCode {
    use std::io::ErrorKind::*;
    match e.kind() {
        NotFound => StatusCode::NoSuchFile,
        PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

/// Build `FileAttributes` from `std::fs::Metadata`.
fn metadata_to_attrs(meta: &std::fs::Metadata) -> FileAttributes {
    FileAttributes::from(meta)
}

/// Build `FileAttributes` from async metadata.
async fn path_attrs(path: &str) -> Result<FileAttributes, StatusCode> {
    let meta = fs::metadata(path).await.map_err(|e| io_to_status(&e))?;
    Ok(metadata_to_attrs(&meta))
}

/// Like `path_attrs` but uses `symlink_metadata` (lstat — does not follow symlinks).
async fn lpath_attrs(path: &str) -> Result<FileAttributes, StatusCode> {
    let meta = fs::symlink_metadata(path)
        .await
        .map_err(|e| io_to_status(&e))?;
    Ok(metadata_to_attrs(&meta))
}

// ---------------------------------------------------------------------------
// russh_sftp::server::Handler implementation
// ---------------------------------------------------------------------------

impl russh_sftp::server::Handler for SftpHandler {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        version: u32,
        extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        if self.version.is_some() {
            error!("duplicate SSH_FXP_INIT");
            return Err(StatusCode::BadMessage);
        }
        self.version = Some(version);
        info!("SFTP init version={}, extensions={:?}", version, extensions);
        Ok(Version::new())
    }

    // -- open / close --------------------------------------------------------

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        info!("SFTP open: {} flags={:?}", filename, pflags);

        let opts: std::fs::OpenOptions = pflags.into();
        let file = tokio::fs::OpenOptions::from(opts)
            .open(&filename)
            .await
            .map_err(|e| {
                error!("SFTP open error: {}", e);
                io_to_status(&e)
            })?;

        let handle = self.alloc_handle();
        self.file_handles.insert(handle.clone(), file);
        Ok(Handle { id, handle })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        info!("SFTP close: {}", handle);
        // Remove from whichever map it lives in.
        self.file_handles.remove(&handle);
        self.dir_handles.remove(&handle);
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    // -- read / write --------------------------------------------------------

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let file = self
            .file_handles
            .get_mut(&handle)
            .ok_or(StatusCode::Failure)?;

        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|e| {
                error!("SFTP read seek error: {}", e);
                io_to_status(&e)
            })?;

        let mut buf = vec![0u8; len as usize];
        let n = file.read(&mut buf).await.map_err(|e| {
            error!("SFTP read error: {}", e);
            io_to_status(&e)
        })?;

        if n == 0 {
            return Err(StatusCode::Eof);
        }

        buf.truncate(n);
        Ok(Data { id, data: buf })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let file = self
            .file_handles
            .get_mut(&handle)
            .ok_or(StatusCode::Failure)?;

        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|e| {
                error!("SFTP write seek error: {}", e);
                io_to_status(&e)
            })?;

        file.write_all(&data).await.map_err(|e| {
            error!("SFTP write error: {}", e);
            io_to_status(&e)
        })?;

        file.flush().await.map_err(|e| {
            error!("SFTP write flush error: {}", e);
            io_to_status(&e)
        })?;

        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    // -- stat / lstat / fstat ------------------------------------------------

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        info!("SFTP stat: {}", path);
        let attrs = path_attrs(&path).await?;
        Ok(Attrs { id, attrs })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        info!("SFTP lstat: {}", path);
        let attrs = lpath_attrs(&path).await?;
        Ok(Attrs { id, attrs })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        info!("SFTP fstat: {}", handle);
        let file = self.file_handles.get(&handle).ok_or(StatusCode::Failure)?;
        let meta = file.metadata().await.map_err(|e| {
            error!("SFTP fstat error: {}", e);
            io_to_status(&e)
        })?;
        let attrs = metadata_to_attrs(&meta);
        Ok(Attrs { id, attrs })
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        info!("SFTP setstat: {}", path);
        // Best-effort: we acknowledge but most attribute changes require
        // platform-specific APIs.  Permissions are handled on Unix below.
        #[cfg(unix)]
        {
            if let Some(perms) = _attrs.permissions {
                use std::os::unix::fs::PermissionsExt;
                let p = std::fs::Permissions::from_mode(perms);
                fs::set_permissions(&path, p).await.map_err(|e| {
                    error!("SFTP setstat chmod error: {}", e);
                    io_to_status(&e)
                })?;
            }
        }
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        info!("SFTP fsetstat: {}", handle);
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    // -- directory operations ------------------------------------------------

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        info!("SFTP opendir: {}", path);
        // Verify the path is a valid directory.
        let meta = fs::metadata(&path).await.map_err(|e| {
            error!("SFTP opendir error: {}", e);
            io_to_status(&e)
        })?;
        if !meta.is_dir() {
            return Err(StatusCode::NoSuchFile);
        }
        let handle = self.alloc_handle();
        self.dir_handles
            .insert(handle.clone(), (PathBuf::from(&path), false));
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        info!("SFTP readdir: {}", handle);
        let (path, read_done) = self
            .dir_handles
            .get_mut(&handle)
            .ok_or(StatusCode::Failure)?;

        if *read_done {
            // Second call — signal end of directory.
            return Err(StatusCode::Eof);
        }

        *read_done = true;
        let dir_path = path.clone();

        let mut entries = fs::read_dir(&dir_path).await.map_err(|e| {
            error!("SFTP readdir error: {}", e);
            io_to_status(&e)
        })?;

        let mut files = Vec::new();

        // Add . and .. entries
        if let Ok(meta) = fs::metadata(&dir_path).await {
            files.push(File::new(".", metadata_to_attrs(&meta)));
        }
        if let Some(parent) = dir_path.parent() {
            if let Ok(meta) = fs::metadata(parent).await {
                files.push(File::new("..", metadata_to_attrs(&meta)));
            }
        } else {
            // Root directory: .. is the same as .
            if let Ok(meta) = fs::metadata(&dir_path).await {
                files.push(File::new("..", metadata_to_attrs(&meta)));
            }
        }

        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Ok(meta) = entry.metadata().await {
                files.push(File::new(name, metadata_to_attrs(&meta)));
            } else {
                files.push(File::new(name, FileAttributes::default()));
            }
        }

        Ok(Name { id, files })
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        info!("SFTP mkdir: {}", path);
        fs::create_dir(&path).await.map_err(|e| {
            error!("SFTP mkdir error: {}", e);
            io_to_status(&e)
        })?;
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        info!("SFTP rmdir: {}", path);
        fs::remove_dir(&path).await.map_err(|e| {
            error!("SFTP rmdir error: {}", e);
            io_to_status(&e)
        })?;
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    // -- file operations -----------------------------------------------------

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        info!("SFTP remove: {}", filename);
        fs::remove_file(&filename).await.map_err(|e| {
            error!("SFTP remove error: {}", e);
            io_to_status(&e)
        })?;
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        info!("SFTP rename: {} -> {}", oldpath, newpath);
        fs::rename(&oldpath, &newpath).await.map_err(|e| {
            error!("SFTP rename error: {}", e);
            io_to_status(&e)
        })?;
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    // -- path operations -----------------------------------------------------

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        info!("SFTP realpath: {}", path);
        let canonical = fs::canonicalize(&path).await.map_err(|e| {
            error!("SFTP realpath error: {}", e);
            io_to_status(&e)
        })?;
        let canon_str = canonical.to_string_lossy().to_string();

        // On Windows, canonicalize returns UNC paths like \\?\C:\...
        // Strip the \\?\ prefix for compatibility with SFTP clients.
        #[cfg(windows)]
        let canon_str = canon_str
            .strip_prefix(r"\\?\")
            .unwrap_or(&canon_str)
            .to_string();

        Ok(Name {
            id,
            files: vec![File::dummy(canon_str)],
        })
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        info!("SFTP readlink: {}", path);
        let target = fs::read_link(&path).await.map_err(|e| {
            error!("SFTP readlink error: {}", e);
            io_to_status(&e)
        })?;
        Ok(Name {
            id,
            files: vec![File::dummy(target.to_string_lossy().to_string())],
        })
    }

    async fn symlink(
        &mut self,
        id: u32,
        linkpath: String,
        targetpath: String,
    ) -> Result<Status, Self::Error> {
        info!("SFTP symlink: {} -> {}", linkpath, targetpath);

        #[cfg(unix)]
        {
            tokio::fs::symlink(&targetpath, &linkpath)
                .await
                .map_err(|e| {
                    error!("SFTP symlink error: {}", e);
                    io_to_status(&e)
                })?;
        }

        #[cfg(windows)]
        {
            // On Windows, we need to know if the target is a directory.
            let is_dir = fs::metadata(&targetpath)
                .await
                .map(|m| m.is_dir())
                .unwrap_or(false);
            if is_dir {
                tokio::fs::symlink_dir(&targetpath, &linkpath)
                    .await
                    .map_err(|e| {
                        error!("SFTP symlink error: {}", e);
                        io_to_status(&e)
                    })?;
            } else {
                tokio::fs::symlink_file(&targetpath, &linkpath)
                    .await
                    .map_err(|e| {
                        error!("SFTP symlink error: {}", e);
                        io_to_status(&e)
                    })?;
            }
        }

        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    async fn extended(
        &mut self,
        _id: u32,
        request: String,
        _data: Vec<u8>,
    ) -> Result<Packet, Self::Error> {
        info!("SFTP extended: {}", request);
        // We don't support any extensions; return OpUnsupported.
        Err(StatusCode::OpUnsupported)
    }
}
