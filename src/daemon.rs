//! Automatic process daemonization.
//!
//! - **Unix**: classic double-fork so the process detaches from any
//!   controlling terminal and runs as a proper daemon.
//! - **Windows**: re-launches itself as a detached, console-less process
//!   when started from a console window.

// ───────────────────────────────────────────────────────────────────────
// Unix implementation
// ───────────────────────────────────────────────────────────────────────
#[cfg(unix)]
pub fn daemonize() {
    use nix::fcntl::OFlag;
    use nix::sys::stat::Mode;
    use nix::unistd::{chdir, dup2, fork, setsid, ForkResult};
    use std::process;

    // --- First fork ---
    // SAFETY: fork() is called before any threads are spawned (we are
    // in synchronous `main` before the Tokio runtime starts).  No
    // async-signal-unsafe functions are called between fork and _exit
    // in the parent path.
    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => process::exit(0),
        Ok(ForkResult::Child) => {}
        Err(e) => {
            log::error!("daemonize: first fork failed: {}", e);
            process::exit(1);
        }
    }

    // New session – detach from controlling terminal.
    if let Err(e) = setsid() {
        log::error!("daemonize: setsid failed: {}", e);
        process::exit(1);
    }

    // --- Second fork ---
    // SAFETY: same rationale as the first fork – still single-threaded,
    // no async-signal-unsafe work in the parent path.
    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => process::exit(0),
        Ok(ForkResult::Child) => {}
        Err(e) => {
            log::error!("daemonize: second fork failed: {}", e);
            process::exit(1);
        }
    }

    // Release directory locks.
    let _ = chdir("/");

    // Redirect stdin/stdout/stderr to /dev/null.
    if let Ok(devnull) = nix::fcntl::open("/dev/null", OFlag::O_RDWR, Mode::empty()) {
        let _ = dup2(devnull, 0); // stdin
        let _ = dup2(devnull, 1); // stdout
        let _ = dup2(devnull, 2); // stderr
        if devnull > 2 {
            let _ = nix::unistd::close(devnull);
        }
    }
}

// ───────────────────────────────────────────────────────────────────────
// Windows implementation
// ───────────────────────────────────────────────────────────────────────
#[cfg(windows)]
pub fn daemonize() {
    use std::process;
    use windows_sys::Win32::System::Console::GetConsoleWindow;
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, CREATE_NO_WINDOW, DETACHED_PROCESS, PROCESS_INFORMATION, STARTUPINFOW,
    };

    // SAFETY: GetConsoleWindow is always safe to call; it returns a
    // window handle or null.
    let hwnd = unsafe { GetConsoleWindow() };

    if hwnd.is_null() {
        // Already running detached – nothing to do.
        return;
    }

    // Re-launch ourselves without a console window.
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            log::error!("daemonize: cannot determine own exe path: {}", e);
            return;
        }
    };

    // Build the full command line (exe + forwarded args).
    let args: Vec<String> = std::env::args().collect();
    let cmdline = args
        .iter()
        .map(|a| {
            if a.contains(' ') {
                format!("\"{}\"", a)
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    // Encode as wide (UTF-16) null-terminated string.
    let wide_cmdline: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_exe: Vec<u16> = exe
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // SAFETY: we pass valid, null-terminated wide strings for the
    // application name and command line.  `si` and `pi` are
    // zero-initialised and correctly sized.  The new process inherits
    // no handles (bInheritHandles = 0).
    let ok = unsafe {
        CreateProcessW(
            wide_exe.as_ptr(),
            wide_cmdline.as_ptr() as *mut _,
            std::ptr::null(), // lpProcessAttributes
            std::ptr::null(), // lpThreadAttributes
            0,                // bInheritHandles = FALSE
            CREATE_NO_WINDOW | DETACHED_PROCESS,
            std::ptr::null(), // lpEnvironment (inherit)
            std::ptr::null(), // lpCurrentDirectory (inherit)
            &si,
            &mut pi,
        )
    };

    if ok != 0 {
        // SAFETY: closing valid handles returned by CreateProcessW.
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(pi.hProcess);
            windows_sys::Win32::Foundation::CloseHandle(pi.hThread);
        }
        // Parent exits; the detached child continues.
        process::exit(0);
    } else {
        log::error!("daemonize: CreateProcessW failed");
    }
}
