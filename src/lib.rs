//! A minimal atproto Personal Data Server.
//!
//! The binary wires these together; each module is usable without a socket.

pub mod config;
pub mod server;
pub mod syntax;
pub mod xrpc;
