//! # Neap
//!
//! Statically-linked SSH server for authorized penetration testing.
//!
//! Neap provides reverse shells, bind shells, SFTP file transfer, and full
//! SSH port forwarding in a single static binary. It is a Rust rewrite of
//! [Undertow](https://github.com/Real-Fruit-Snacks/Undertow).

#![warn(clippy::all)]
#![warn(missing_docs)]

pub mod config;
pub mod error;
pub mod info;
pub mod memfs;
