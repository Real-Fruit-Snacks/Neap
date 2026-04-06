// Windows ConPTY implementation — spawn a shell inside a pseudo-console.
//
// This entire module is gated behind `#[cfg(windows)]` in `pty/mod.rs`,
// so it is never compiled on Unix.

use std::io;
use std::mem;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE, INVALID_HANDLE_VALUE, S_OK};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::Console::{
    ClosePseudoConsole, CreatePseudoConsole, ResizePseudoConsole, COORD, HPCON,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, UpdateProcThreadAttribute, WaitForSingleObject,
    EXTENDED_STARTUPINFO_PRESENT, INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, STARTUPINFOEXW, STARTUPINFOW,
};

use crate::pty::WinSize;

// ---------------------------------------------------------------------------
// ConPTY support detection
// ---------------------------------------------------------------------------

/// Check if the current Windows build supports ConPTY (Windows 10 build 17763+).
///
/// We probe by attempting to create a tiny dummy pseudo-console and immediately
/// closing it.  If `CreatePseudoConsole` succeeds the API is available.
pub fn supports_conpty() -> bool {
    // SAFETY: All HANDLE arguments are valid — created by prior successful API calls
    // in this function. NULL checks are performed after each call.
    unsafe {
        // Create a disposable pipe pair for the probe.
        let mut pipe_in_read: HANDLE = INVALID_HANDLE_VALUE;
        let mut pipe_in_write: HANDLE = INVALID_HANDLE_VALUE;
        let mut pipe_out_read: HANDLE = INVALID_HANDLE_VALUE;
        let mut pipe_out_write: HANDLE = INVALID_HANDLE_VALUE;

        if CreatePipe(&mut pipe_in_read, &mut pipe_in_write, ptr::null(), 0) == FALSE {
            return false;
        }
        if CreatePipe(&mut pipe_out_read, &mut pipe_out_write, ptr::null(), 0) == FALSE {
            CloseHandle(pipe_in_read);
            CloseHandle(pipe_in_write);
            return false;
        }

        let size = COORD { X: 80, Y: 25 };
        let mut h_pc: HPCON = 0;
        let hr = CreatePseudoConsole(size, pipe_in_read, pipe_out_write, 0, &mut h_pc);

        // Clean up regardless of outcome.
        if hr == S_OK {
            ClosePseudoConsole(h_pc);
        }
        CloseHandle(pipe_in_read);
        CloseHandle(pipe_in_write);
        CloseHandle(pipe_out_read);
        CloseHandle(pipe_out_write);

        hr == S_OK
    }
}

// ---------------------------------------------------------------------------
// ConPtyHandle — owns the pseudo-console and spawned process
// ---------------------------------------------------------------------------

/// Owns a Windows ConPTY pseudo-console session, including the spawned process
/// and the pipe handles used for I/O.
pub struct ConPtyHandle {
    /// The pseudo console handle.
    h_pc: HPCON,
    /// Write to this handle to send input to the ConPTY.
    pipe_in: HANDLE,
    /// Read from this handle to receive output from the ConPTY.
    pipe_out: HANDLE,
    /// The spawned process handle.
    process: HANDLE,
    /// The spawned thread handle.
    thread: HANDLE,
}

// SAFETY: ConPtyHandle exclusively owns all Win32 HANDLEs.
// The handles are not aliased or shared — only one ConPtyHandle
// exists per pseudo-console. Read/write operations use the handles
// sequentially via &self methods.
unsafe impl Send for ConPtyHandle {}
unsafe impl Sync for ConPtyHandle {}

impl ConPtyHandle {
    /// Spawn a shell inside a ConPTY with the given terminal dimensions.
    ///
    /// If `shell` is a Unix-style path (starts with `/`), falls back to PowerShell.
    pub fn spawn(shell: &str, win_size: &WinSize) -> io::Result<Self> {
        // SAFETY: All HANDLE arguments are valid — created by prior successful API calls
        // in this function. NULL checks are performed after each call.
        unsafe {
            // ---------------------------------------------------------------
            // 1. Create two pipe pairs.
            //    Pair 1: pty_input_read  (ConPTY reads from here)
            //            pty_input_write (we write to this → goes to ConPTY stdin)
            //    Pair 2: pty_output_read (we read from this ← ConPTY stdout)
            //            pty_output_write (ConPTY writes to here)
            // ---------------------------------------------------------------
            let mut pty_input_read: HANDLE = INVALID_HANDLE_VALUE;
            let mut pty_input_write: HANDLE = INVALID_HANDLE_VALUE;
            let mut pty_output_read: HANDLE = INVALID_HANDLE_VALUE;
            let mut pty_output_write: HANDLE = INVALID_HANDLE_VALUE;

            if CreatePipe(&mut pty_input_read, &mut pty_input_write, ptr::null(), 0) == FALSE {
                return Err(io::Error::last_os_error());
            }
            if CreatePipe(&mut pty_output_read, &mut pty_output_write, ptr::null(), 0) == FALSE {
                CloseHandle(pty_input_read);
                CloseHandle(pty_input_write);
                return Err(io::Error::last_os_error());
            }

            // ---------------------------------------------------------------
            // 2. Create the pseudo-console.
            // ---------------------------------------------------------------
            let size = COORD {
                X: win_size.cols as i16,
                Y: win_size.rows as i16,
            };
            let mut h_pc: HPCON = 0;
            let hr = CreatePseudoConsole(size, pty_input_read, pty_output_write, 0, &mut h_pc);
            if hr != S_OK {
                CloseHandle(pty_input_read);
                CloseHandle(pty_input_write);
                CloseHandle(pty_output_read);
                CloseHandle(pty_output_write);
                return Err(io::Error::from_raw_os_error(hr));
            }

            // Close the PTY-side pipe ends — ConPTY owns them now.
            CloseHandle(pty_input_read);
            CloseHandle(pty_output_write);

            // ---------------------------------------------------------------
            // 3. Set up the process attribute list with the pseudo-console.
            // ---------------------------------------------------------------
            let mut attr_list_size: usize = 0;

            // First call: query the required size.
            InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut attr_list_size);
            // This call is expected to fail with ERROR_INSUFFICIENT_BUFFER;
            // we only need the size.

            let attr_list_buf = vec![0u8; attr_list_size];
            let attr_list: LPPROC_THREAD_ATTRIBUTE_LIST =
                attr_list_buf.as_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;

            if InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_list_size) == FALSE {
                ClosePseudoConsole(h_pc);
                CloseHandle(pty_input_write);
                CloseHandle(pty_output_read);
                return Err(io::Error::last_os_error());
            }

            if UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                h_pc as *const core::ffi::c_void,
                mem::size_of::<HPCON>(),
                ptr::null_mut(),
                ptr::null(),
            ) == FALSE
            {
                DeleteProcThreadAttributeList(attr_list);
                ClosePseudoConsole(h_pc);
                CloseHandle(pty_input_write);
                CloseHandle(pty_output_read);
                return Err(io::Error::last_os_error());
            }

            // ---------------------------------------------------------------
            // 4. Spawn the shell via CreateProcessW.
            // ---------------------------------------------------------------
            let mut startup_info: STARTUPINFOEXW = mem::zeroed();
            startup_info.StartupInfo.cb = mem::size_of::<STARTUPINFOEXW>() as u32;
            startup_info.lpAttributeList = attr_list;

            let mut proc_info: PROCESS_INFORMATION = mem::zeroed();

            // If the caller passed a Unix-style default (e.g. "/bin/bash"),
            // fall back to PowerShell since that path doesn't exist on Windows.
            let shell_path = if shell.starts_with('/') {
                r"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe"
            } else {
                shell
            };

            // Shell path as a null-terminated wide string.
            let cmd_line: Vec<u16> = format!("{}\0", shell_path).encode_utf16().collect();
            // CreateProcessW requires a mutable command line buffer.
            let mut cmd_line_buf = cmd_line;

            let success = CreateProcessW(
                ptr::null(),                                                   // lpApplicationName
                cmd_line_buf.as_mut_ptr(),                                     // lpCommandLine
                ptr::null(),                  // lpProcessAttributes
                ptr::null(),                  // lpThreadAttributes
                FALSE,                        // bInheritHandles
                EXTENDED_STARTUPINFO_PRESENT, // dwCreationFlags
                ptr::null(),                  // lpEnvironment
                ptr::null(),                  // lpCurrentDirectory
                &startup_info as *const STARTUPINFOEXW as *const STARTUPINFOW, // lpStartupInfo
                &mut proc_info,               // lpProcessInformation
            );

            // Clean up the attribute list (we no longer need it).
            DeleteProcThreadAttributeList(attr_list);

            if success == FALSE {
                let err = io::Error::last_os_error();
                ClosePseudoConsole(h_pc);
                CloseHandle(pty_input_write);
                CloseHandle(pty_output_read);
                return Err(err);
            }

            Ok(ConPtyHandle {
                h_pc,
                pipe_in: pty_input_write,
                pipe_out: pty_output_read,
                process: proc_info.hProcess,
                thread: proc_info.hThread,
            })
        }
    }

    /// Resize the pseudo-console to the given dimensions.
    pub fn resize(&self, win_size: &WinSize) -> io::Result<()> {
        let size = COORD {
            X: win_size.cols as i16,
            Y: win_size.rows as i16,
        };
        // SAFETY: self.h_pc is a valid pseudo-console handle created in spawn().
        let hr = unsafe { ResizePseudoConsole(self.h_pc, size) };
        if hr != S_OK {
            return Err(io::Error::from_raw_os_error(hr));
        }
        Ok(())
    }

    /// Blocking read from the ConPTY output pipe.
    ///
    /// Returns the number of bytes read, or 0 on EOF / pipe closed.
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut bytes_read: u32 = 0;
        // SAFETY: self.pipe_out is a valid handle created in spawn().
        // buf is a valid mutable slice and bytes_read is properly initialized.
        let ok = unsafe {
            ReadFile(
                self.pipe_out,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut bytes_read,
                ptr::null_mut(),
            )
        };
        if ok == FALSE {
            let err = io::Error::last_os_error();
            // ERROR_BROKEN_PIPE (109) means the other end closed — treat as EOF.
            if err.raw_os_error() == Some(109) {
                return Ok(0);
            }
            return Err(err);
        }
        Ok(bytes_read as usize)
    }

    /// Blocking write to the ConPTY input pipe.
    pub fn write(&self, data: &[u8]) -> io::Result<usize> {
        let mut bytes_written: u32 = 0;
        // SAFETY: self.pipe_in is a valid handle created in spawn().
        // data is a valid slice and bytes_written is properly initialized.
        let ok = unsafe {
            WriteFile(
                self.pipe_in,
                data.as_ptr(),
                data.len() as u32,
                &mut bytes_written,
                ptr::null_mut(),
            )
        };
        if ok == FALSE {
            return Err(io::Error::last_os_error());
        }
        Ok(bytes_written as usize)
    }

    /// Block until the spawned process exits, then return its exit code.
    #[allow(dead_code)]
    pub fn wait(&self) -> io::Result<u32> {
        // SAFETY: self.process is a valid handle created by CreateProcessW in spawn().
        unsafe {
            WaitForSingleObject(self.process, INFINITE);
            let mut exit_code: u32 = 0;
            if GetExitCodeProcess(self.process, &mut exit_code) == FALSE {
                return Err(io::Error::last_os_error());
            }
            Ok(exit_code)
        }
    }
}

impl Drop for ConPtyHandle {
    fn drop(&mut self) {
        // SAFETY: All handles are valid — created by successful API calls in spawn().
        // Each handle is closed exactly once here; after drop, no further access occurs.
        unsafe {
            // Close the pseudo-console first so the process receives EOF.
            ClosePseudoConsole(self.h_pc);
            // Close the I/O pipes.
            CloseHandle(self.pipe_in);
            CloseHandle(self.pipe_out);
            // Close process and thread handles.
            CloseHandle(self.process);
            CloseHandle(self.thread);
        }
    }
}

// ---------------------------------------------------------------------------
// Legacy fallback message
// ---------------------------------------------------------------------------

/// Return an error message for Windows systems that lack ConPTY support.
pub fn deny_pty_legacy() -> &'static str {
    "No ConPTY shell or ssh-shellhost enhanced shell available. \
     Please append 'cmd' to your ssh command to get a basic command prompt."
}
