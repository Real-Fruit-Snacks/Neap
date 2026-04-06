#[cfg(unix)]
pub mod unix;

#[cfg(windows)]
pub mod windows;

/// Terminal window size parameters.
#[derive(Debug, Clone, Copy)]
pub struct WinSize {
    pub cols: u16,
    pub rows: u16,
    #[allow(dead_code)]
    pub pix_width: u16,
    #[allow(dead_code)]
    pub pix_height: u16,
}

/// PTY information associated with a channel.
#[derive(Debug, Clone)]
pub struct PtyInfo {
    #[allow(dead_code)]
    pub term: String,
    pub win_size: WinSize,
}
