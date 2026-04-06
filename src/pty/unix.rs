// Unix PTY implementation — spawn a shell in a new pseudo-terminal.
//
// This entire module is gated behind `#[cfg(unix)]` in `pty/mod.rs`,
// so it is never compiled on Windows.

use std::ffi::CString;
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};

use nix::pty::{openpty, OpenptyResult};
use nix::unistd::{close, dup2, execvp, fork, setsid, ForkResult};

use crate::pty::WinSize;

// ---------------------------------------------------------------------------
// Window-size ioctl
// ---------------------------------------------------------------------------

/// Set the terminal window size on a PTY master file descriptor.
///
/// Uses the `TIOCSWINSZ` ioctl directly via libc.
pub fn set_win_size(fd: RawFd, win_size: &WinSize) -> std::io::Result<()> {
    let ws = libc::winsize {
        ws_row: win_size.rows,
        ws_col: win_size.cols,
        ws_xpixel: win_size.pix_width,
        ws_ypixel: win_size.pix_height,
    };
    // SAFETY: TIOCSWINSZ is a valid ioctl for terminal fds.
    // The winsize struct is properly initialized and passed by reference.
    let ret = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shell spawning
// ---------------------------------------------------------------------------

/// Spawn `shell` inside a newly-created PTY.
///
/// Returns the master side of the PTY as an `OwnedFd`.  The caller is
/// responsible for reading/writing the master fd to relay I/O to/from the
/// shell process.
///
/// # Safety
///
/// Calls `fork()`, which is inherently unsafe in a multi-threaded program.
/// The child process immediately calls only async-signal-safe functions
/// (`setsid`, `ioctl`, `dup2`, `close`, `execvp`) and `_exit`, so this is
/// safe provided the caller does not hold locks that the child would need.
pub fn spawn_shell(shell: &str, term: &str, win_size: &WinSize) -> std::io::Result<OwnedFd> {
    // Open a new PTY master/slave pair.
    let OpenptyResult { master, slave } =
        openpty(None, None).map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;

    // Set the initial window size on the master fd.
    set_win_size(master.as_raw_fd(), win_size)?;

    // Fork the process.
    // SAFETY: fork() is called before any multi-threaded tokio runtime
    // operations on the child side. The child immediately calls setsid,
    // dup2, and execvp without touching shared state.
    let fork_result = unsafe { fork() }.map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;

    match fork_result {
        ForkResult::Child => {
            // ---------------------------------------------------------------
            // CHILD PROCESS
            // Only async-signal-safe functions from here until execvp/_exit.
            // ---------------------------------------------------------------

            // Drop the master fd in the child — we only need the slave side.
            drop(master);

            // Create a new session and become session leader.
            let _ = setsid();

            // Set the slave as the controlling terminal (TIOCSCTTY).
            // The second argument 0 means "don't steal if already owned".
            // SAFETY: TIOCSCTTY is a valid ioctl for terminal fds after setsid().
            // The slave fd is a valid PTY slave obtained from openpty().
            unsafe {
                libc::ioctl(slave.as_raw_fd(), libc::TIOCSCTTY, 0);
            }

            // Redirect stdin/stdout/stderr to the slave PTY.
            let slave_fd = slave.as_raw_fd();
            let _ = dup2(slave_fd, 0); // stdin
            let _ = dup2(slave_fd, 1); // stdout
            let _ = dup2(slave_fd, 2); // stderr

            // Close the original slave fd if it isn't one of 0/1/2.
            if slave_fd > 2 {
                let _ = close(slave_fd);
            }
            // Ensure the OwnedFd doesn't try to close again.
            std::mem::forget(slave);

            // Set environment variables.
            // Note: std::env::set_var is not async-signal-safe, but these
            // libc calls are (putenv/setenv are specified as AS-safe on most
            // platforms, and we exec immediately after).
            // SAFETY: All CString values are constructed from known-safe
            // literals via unwrap_unchecked (no NUL bytes possible).
            // setenv and getpwuid are AS-safe on POSIX. The pw_dir pointer
            // is valid for the lifetime of this call (no intervening getpw*).
            unsafe {
                let term_key = CString::new("TERM").unwrap_unchecked();
                let term_val = CString::new(term).unwrap_unchecked();
                libc::setenv(term_key.as_ptr(), term_val.as_ptr(), 1);

                // Set HOME to the passwd entry if available, else "/".
                let uid = libc::getuid();
                let pw = libc::getpwuid(uid);
                if !pw.is_null() && !(*pw).pw_dir.is_null() {
                    let home_key = CString::new("HOME").unwrap_unchecked();
                    libc::setenv(home_key.as_ptr(), (*pw).pw_dir, 1);
                }
            }

            // Execute the shell.  execvp replaces the process image; if it
            // returns, something went wrong.
            let shell_c = CString::new(shell).unwrap_or_else(|_| {
                // If the shell path contains a nul byte, fall back.
                CString::new("/bin/sh").expect("shell path contains no NUL bytes")
            });
            // argv[0] is typically just the shell name (e.g. "-bash" for login
            // shell or "bash").  We use a login-shell convention by prefixing
            // with '-'.
            let argv0 = CString::new(format!("-{}", shell.rsplit('/').next().unwrap_or(shell)))
                .unwrap_or_else(|_| {
                    CString::new("-sh").expect("fallback shell name contains no NUL bytes")
                });
            let argv = [argv0.clone()];
            let _ = execvp(&shell_c, &argv);

            // execvp failed — exit immediately.
            // SAFETY: _exit is async-signal-safe and terminates the child
            // process without running destructors or atexit handlers.
            unsafe { libc::_exit(127) };
        }
        ForkResult::Parent { child: _child } => {
            // ---------------------------------------------------------------
            // PARENT PROCESS
            // ---------------------------------------------------------------

            // Drop the slave fd — the parent only needs the master side.
            drop(slave);

            Ok(master)
        }
    }
}
