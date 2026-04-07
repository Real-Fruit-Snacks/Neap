//! SFTP subsystem handler backed by the in-memory filesystem ([`MemFs`]).
//!
//! Implements `russh_sftp::server::Handler` identically to [`crate::sftp::SftpHandler`]
//! but performs all I/O against a [`SharedMemFs`] instead of the real disk.
//! This means file transfers leave zero artifacts on the target host.

use std::collections::HashMap;
use std::path::PathBuf;

use log::{error, info};
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Packet, Status, StatusCode, Version,
};

use crate::exec;
use crate::memfs::{MemMetadata, SharedMemFs};

/// State for a single in-memory SFTP session.
pub struct MemSftpHandler {
    /// Protocol version negotiated with the client.
    version: Option<u32>,
    /// Monotonically increasing counter for generating unique handle IDs.
    next_handle: u64,
    /// Open file handles: handle-string -> (path, cursor offset).
    file_handles: HashMap<String, (PathBuf, u64)>,
    /// Open directory handles: handle-string -> (path, already-read flag).
    dir_handles: HashMap<String, (PathBuf, bool)>,
    /// Handles for `/exec/` command output: handle-string -> output bytes.
    exec_handles: HashMap<String, Vec<u8>>,
    /// Shared reference to the in-memory filesystem.
    memfs: SharedMemFs,
}

impl MemSftpHandler {
    /// Create a new handler backed by the given shared in-memory filesystem.
    pub fn new(memfs: SharedMemFs) -> Self {
        Self {
            version: None,
            next_handle: 0,
            file_handles: HashMap::new(),
            dir_handles: HashMap::new(),
            exec_handles: HashMap::new(),
            memfs,
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

/// Convert [`MemMetadata`] to SFTP [`FileAttributes`].
fn mem_meta_to_attrs(meta: &MemMetadata) -> FileAttributes {
    // Convert SystemTime to Unix timestamp for the SFTP modified time.
    let (atime, mtime) = if let Ok(dur) = meta.modified.duration_since(std::time::UNIX_EPOCH) {
        let secs = dur.as_secs() as u32;
        (Some(secs), Some(secs))
    } else {
        (None, None)
    };

    FileAttributes {
        size: Some(meta.size),
        permissions: Some(meta.permissions),
        // Encode uid/gid as 0 (root) -- in-memory FS has no real owner.
        uid: Some(0),
        gid: Some(0),
        atime,
        mtime,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// russh_sftp::server::Handler implementation
// ---------------------------------------------------------------------------

impl russh_sftp::server::Handler for MemSftpHandler {
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
        info!(
            "MemSFTP init version={}, extensions={:?}",
            version, extensions
        );
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
        info!("MemSFTP open: {} flags={:?}", filename, pflags);

        // Intercept /exec/<cmd> paths — use memfs-aware execution so
        // commands can reference files that were uploaded into memory.
        if let Some(cmd) = exec::extract_command(&filename) {
            info!("MemSFTP exec open: running {:?}", cmd);
            let output = {
                let fs = self.memfs.read().map_err(|_| {
                    error!("MemSFTP exec: lock poisoned");
                    StatusCode::Failure
                })?;
                exec::run_command_with_memfs(cmd, &fs)
            };
            let handle = self.alloc_handle();
            self.exec_handles.insert(handle.clone(), output);
            return Ok(Handle { id, handle });
        }

        // If CREATE flag is set and the file doesn't exist, create it.
        if pflags.contains(OpenFlags::CREATE) {
            let mut fs = self.memfs.write().map_err(|_| {
                error!("MemSFTP open: lock poisoned");
                StatusCode::Failure
            })?;
            let path = fs.normalize(&filename);
            if !fs.exists(&path) {
                fs.create_file(&path, Vec::new()).map_err(|e| {
                    error!("MemSFTP open create error: {}", e);
                    io_to_status(&e)
                })?;
            }
        }

        // Verify the file exists.
        {
            let fs = self.memfs.read().map_err(|_| {
                error!("MemSFTP open: lock poisoned");
                StatusCode::Failure
            })?;
            let path = fs.normalize(&filename);
            if !fs.exists(&path) || fs.is_dir(&path) {
                return Err(StatusCode::NoSuchFile);
            }
        }

        // If TRUNCATE flag is set, truncate the file to zero length.
        if pflags.contains(OpenFlags::TRUNCATE) {
            let mut fs = self.memfs.write().map_err(|_| {
                error!("MemSFTP open: lock poisoned");
                StatusCode::Failure
            })?;
            let path = fs.normalize(&filename);
            fs.create_file(&path, Vec::new()).map_err(|e| {
                error!("MemSFTP open truncate error: {}", e);
                io_to_status(&e)
            })?;
        }

        let fs = self.memfs.read().map_err(|_| StatusCode::Failure)?;
        let path = fs.normalize(&filename);
        drop(fs);

        let handle = self.alloc_handle();
        self.file_handles.insert(handle.clone(), (path, 0));
        Ok(Handle { id, handle })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        info!("MemSFTP close: {}", handle);
        self.file_handles.remove(&handle);
        self.dir_handles.remove(&handle);
        self.exec_handles.remove(&handle);
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
        // Serve reads from exec output if this is an exec handle.
        if let Some(output) = self.exec_handles.get(&handle) {
            let start = offset as usize;
            if start >= output.len() {
                return Err(StatusCode::Eof);
            }
            let end = std::cmp::min(start + len as usize, output.len());
            return Ok(Data {
                id,
                data: output[start..end].to_vec(),
            });
        }

        let (path, _) = self.file_handles.get(&handle).ok_or(StatusCode::Failure)?;
        let path = path.clone();

        let fs = self.memfs.read().map_err(|_| {
            error!("MemSFTP read: lock poisoned");
            StatusCode::Failure
        })?;

        let data = fs.read_at(&path, offset, len as u64).map_err(|e| {
            error!("MemSFTP read error: {}", e);
            io_to_status(&e)
        })?;

        if data.is_empty() {
            return Err(StatusCode::Eof);
        }

        Ok(Data { id, data })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let (path, _) = self.file_handles.get(&handle).ok_or(StatusCode::Failure)?;
        let path = path.clone();

        let mut fs = self.memfs.write().map_err(|_| {
            error!("MemSFTP write: lock poisoned");
            StatusCode::Failure
        })?;

        // Create file if it doesn't exist (write-through semantics).
        if !fs.exists(&path) {
            fs.create_file(&path, Vec::new()).map_err(|e| {
                error!("MemSFTP write create error: {}", e);
                io_to_status(&e)
            })?;
        }

        fs.write_at(&path, offset, &data).map_err(|e| {
            error!("MemSFTP write error: {}", e);
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
        info!("MemSFTP stat: {}", path);

        if exec::is_exec_path(&path) {
            let attrs = if let Some(cmd) = exec::extract_command(&path) {
                let output = exec::run_command(cmd);
                exec::exec_file_attrs(output.len() as u64)
            } else {
                exec::exec_dir_attrs()
            };
            return Ok(Attrs { id, attrs });
        }

        let fs = self.memfs.read().map_err(|_| StatusCode::Failure)?;
        let meta = fs.stat(&path).map_err(|e| io_to_status(&e))?;
        Ok(Attrs {
            id,
            attrs: mem_meta_to_attrs(&meta),
        })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        info!("MemSFTP lstat: {}", path);

        if exec::is_exec_path(&path) {
            let attrs = if let Some(cmd) = exec::extract_command(&path) {
                let output = exec::run_command(cmd);
                exec::exec_file_attrs(output.len() as u64)
            } else {
                exec::exec_dir_attrs()
            };
            return Ok(Attrs { id, attrs });
        }

        // No symlinks in MemFs, so lstat == stat.
        let fs = self.memfs.read().map_err(|_| StatusCode::Failure)?;
        let meta = fs.stat(&path).map_err(|e| io_to_status(&e))?;
        Ok(Attrs {
            id,
            attrs: mem_meta_to_attrs(&meta),
        })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        info!("MemSFTP fstat: {}", handle);
        let (path, _) = self.file_handles.get(&handle).ok_or(StatusCode::Failure)?;
        let path = path.clone();

        let fs = self.memfs.read().map_err(|_| StatusCode::Failure)?;
        let meta = fs.stat(&path).map_err(|e| {
            error!("MemSFTP fstat error: {}", e);
            io_to_status(&e)
        })?;
        Ok(Attrs {
            id,
            attrs: mem_meta_to_attrs(&meta),
        })
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        info!("MemSFTP setstat: {}", path);
        if let Some(perms) = _attrs.permissions {
            let mut fs = self.memfs.write().map_err(|_| StatusCode::Failure)?;
            fs.set_permissions(&path, perms).map_err(|e| {
                error!("MemSFTP setstat chmod error: {}", e);
                io_to_status(&e)
            })?;
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
        info!("MemSFTP fsetstat: {}", handle);
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    // -- directory operations ------------------------------------------------

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        info!("MemSFTP opendir: {}", path);

        // /exec/ is a virtual directory — no filesystem check needed.
        if exec::is_exec_path(&path) && exec::extract_command(&path).is_none() {
            let handle = self.alloc_handle();
            self.dir_handles
                .insert(handle.clone(), (PathBuf::from("/exec/"), false));
            return Ok(Handle { id, handle });
        }

        let fs = self.memfs.read().map_err(|_| {
            error!("MemSFTP opendir: lock poisoned");
            StatusCode::Failure
        })?;
        let normalized = fs.normalize(&path);
        if !fs.is_dir(&normalized) {
            return Err(StatusCode::NoSuchFile);
        }
        drop(fs);

        let handle = self.alloc_handle();
        self.dir_handles.insert(handle.clone(), (normalized, false));
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        info!("MemSFTP readdir: {}", handle);
        let (path, read_done) = self
            .dir_handles
            .get_mut(&handle)
            .ok_or(StatusCode::Failure)?;

        if *read_done {
            return Err(StatusCode::Eof);
        }

        *read_done = true;
        let dir_path = path.clone();

        // Virtual /exec/ directory — return only . and .. entries.
        if dir_path.as_os_str() == "/exec/" {
            let dir_attrs = exec::exec_dir_attrs();
            let files = vec![
                File::new(".", dir_attrs.clone()),
                File::new("..", dir_attrs),
            ];
            return Ok(Name { id, files });
        }

        let fs = self.memfs.read().map_err(|_| {
            error!("MemSFTP readdir: lock poisoned");
            StatusCode::Failure
        })?;

        let mut files = Vec::new();

        // Add "." entry
        if let Ok(meta) = fs.stat(&dir_path) {
            files.push(File::new(".", mem_meta_to_attrs(&meta)));
        }

        // Add ".." entry
        if let Some(parent) = dir_path.parent() {
            if let Ok(meta) = fs.stat(parent) {
                files.push(File::new("..", mem_meta_to_attrs(&meta)));
            }
        } else {
            // Root directory: .. is the same as .
            if let Ok(meta) = fs.stat(&dir_path) {
                files.push(File::new("..", mem_meta_to_attrs(&meta)));
            }
        }

        // Add child entries
        let entries = fs.list_dir(&dir_path).map_err(|e| {
            error!("MemSFTP readdir error: {}", e);
            io_to_status(&e)
        })?;

        for (name, meta) in entries {
            files.push(File::new(name, mem_meta_to_attrs(&meta)));
        }

        Ok(Name { id, files })
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        info!("MemSFTP mkdir: {}", path);
        let mut fs = self.memfs.write().map_err(|_| StatusCode::Failure)?;
        fs.mkdir(&path).map_err(|e| {
            error!("MemSFTP mkdir error: {}", e);
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
        info!("MemSFTP rmdir: {}", path);
        let mut fs = self.memfs.write().map_err(|_| StatusCode::Failure)?;
        fs.remove_dir(&path).map_err(|e| {
            error!("MemSFTP rmdir error: {}", e);
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
        info!("MemSFTP remove: {}", filename);
        let mut fs = self.memfs.write().map_err(|_| StatusCode::Failure)?;
        fs.remove_file(&filename).map_err(|e| {
            error!("MemSFTP remove error: {}", e);
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
        info!("MemSFTP rename: {} -> {}", oldpath, newpath);
        let mut fs = self.memfs.write().map_err(|_| StatusCode::Failure)?;
        fs.rename(&oldpath, &newpath).map_err(|e| {
            error!("MemSFTP rename error: {}", e);
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
        info!("MemSFTP realpath: {}", path);

        // Virtual /exec/ paths resolve to themselves.
        if exec::is_exec_path(&path) {
            let resolved = if exec::extract_command(&path).is_some() {
                path
            } else {
                "/exec/".to_string()
            };
            return Ok(Name {
                id,
                files: vec![File::dummy(resolved)],
            });
        }

        let fs = self.memfs.read().map_err(|_| StatusCode::Failure)?;
        let normalized = fs.normalize(&path);
        let canon_str = normalized.to_string_lossy().to_string();
        Ok(Name {
            id,
            files: vec![File::dummy(canon_str)],
        })
    }

    async fn readlink(&mut self, _id: u32, path: String) -> Result<Name, Self::Error> {
        info!("MemSFTP readlink: {}", path);
        // No symlinks in MemFs.
        Err(StatusCode::OpUnsupported)
    }

    async fn symlink(
        &mut self,
        _id: u32,
        _linkpath: String,
        _targetpath: String,
    ) -> Result<Status, Self::Error> {
        info!("MemSFTP symlink: not supported in memory filesystem");
        Err(StatusCode::OpUnsupported)
    }

    async fn extended(
        &mut self,
        _id: u32,
        request: String,
        _data: Vec<u8>,
    ) -> Result<Packet, Self::Error> {
        info!("MemSFTP extended: {}", request);
        Err(StatusCode::OpUnsupported)
    }
}
