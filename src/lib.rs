//! A minimal atproto Personal Data Server.
//!
//! The binary wires these together; each module is usable without a socket.

pub mod account;
pub mod config;
pub mod crypto;
pub mod event;
pub mod plc;
pub mod repo;
pub mod server;
pub mod store;
pub mod syntax;
pub mod xrpc;
