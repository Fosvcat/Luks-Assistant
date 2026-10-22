//! Core of luks-assistant: reads LUKS2 headers, builds a 32-slot model, keeps slot
//! notes, evaluates TPM2 policies against the current PCR values, and plans
//! and executes key-slot operations behind a set of safety guards.
//!
//! Every write is expressed as a [`ops::Plan`]: a list of steps whose
//! equivalent shell commands can be shown to the user before anything runs.
//! The plan/execute split is what a future privileged D-Bus helper will
//! expose, so frontends never build command lines themselves.

pub mod ctx;
pub mod device;
pub mod error;
pub mod exec;
pub mod guard;
pub mod header;
pub mod health;
pub mod notes;
pub mod ops;
pub mod pcr;
pub mod secret;
pub mod slots;
pub mod util;

pub use ctx::{Ctx, Paths};
pub use error::{Error, Result};
pub use secret::Secret;

/// LUKS2 supports at most 32 key slots (and 32 tokens).
pub const MAX_SLOTS: u32 = 32;
