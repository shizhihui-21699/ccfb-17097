//! credops — find credentials on command lines, in environments and in shell
//! history, then migrate them onto protected channels.
//!
//! The crate is split so that the analysis is testable without a Linux host:
//!
//! * [`scan`] — lexing, the tool knowledge base and the detectors. Pure.
//! * [`model`] — findings that are safe to log, print and ship.
//! * [`collect`] — reading real sources: `/proc`, files, audit logs.
//! * [`remediate`] — turning findings into a migration plan.
//! * [`report`] — rendering.
//!
//! Only [`collect::proc`] and [`run`] touch Linux-specific interfaces; every
//! other module compiles and is tested on any platform.

pub mod collect;
pub mod model;
pub mod remediate;
pub mod report;
pub mod run;
pub mod scan;

pub use model::{Finding, Severity};
