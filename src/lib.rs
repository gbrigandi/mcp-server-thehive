//! # MCP Server for TheHive
//!
//! This library provides an MCP (Model Context Protocol) server implementation
//! for TheHive incident response platform. It allows AI models and automation
//! scripts to interact with TheHive through a standardized protocol.
//!
//! ## Features
//!
//! - Retrieve alerts and cases from TheHive
//! - Get detailed information about specific alerts and cases
//! - Promote alerts to cases
//! - Create new cases in TheHive
//! - Full integration with TheHive API through the thehive-client-rs library
//!
//! ## Usage
//!
//! The server is typically run as a standalone binary that communicates
//! over stdio with MCP clients.

pub mod thehive;

pub use thehive::{client::TheHiveClient, error::TheHiveApiError};
