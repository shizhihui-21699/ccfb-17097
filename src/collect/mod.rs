//! Collectors: where text comes from.
//!
//! Two families, because they answer different questions.
//!
//! **Static sources** (files, cron, systemd, history) are complete and stable:
//! they tell you *which script or job* is wrong even if the job has not run for
//! a month. They are the right place to fix things.
//!
//! **Runtime sources** (`/proc`, auditd, eBPF) catch credentials that only
//! exist while a process is alive. A short-lived process is the hard case:
//! polling `/proc` at, say, 100 ms has a duty cycle of well under 1 %, so it
//! will miss almost everything. The only reliable answers are kernel-side:
//!
//! * `auditd` with an `execve` rule records `EXECVE` (argv as separate `a0`,
//!   `a1`, ... fields) and `PROCTITLE` (the NUL-joined command line) at the
//!   moment of `execve`, with no sampling. This is the recommended default.
//! * eBPF on `sched_process_exec` sees every exec with a ring buffer; see
//!   [`bpf`] for an outline and the tradeoffs.
//! * `/proc` polling is a best-effort fallback for long-lived daemons.

pub mod audit;
pub mod bpf;
pub mod files;
pub mod proc;

use crate::model::Finding;

/// A source of findings, so the CLI can treat all of them uniformly.
pub trait Collector {
    fn name(&self) -> &'static str;
    fn collect(&mut self) -> anyhow::Result<Vec<Finding>>;
}

/// Deduplicate findings that came from overlapping sources (a script that also
/// appears in a crontab, a cmdline seen by both auditd and `/proc`), keeping
/// the one from the more authoritative surface.
pub fn dedup(findings: Vec<Finding>) -> Vec<Finding> {
    use std::collections::HashMap;
    let mut best: HashMap<String, Finding> = HashMap::new();
    for f in findings {
        let key = f.dedup_key();
        match best.get(&key) {
            None => {
                best.insert(key, f);
            }
            Some(existing) => {
                if authority(&f) > authority(existing) {
                    best.insert(key, f);
                }
            }
        }
    }
    let mut out: Vec<Finding> = best.into_values().collect();
    out.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.location.display.cmp(&b.location.display))
            .then_with(|| a.span.start.cmp(&b.span.start))
    });
    out
}

fn authority(f: &Finding) -> u8 {
    use crate::model::Surface::*;
    match f.location.surface {
        // A static file tells you where to fix it; a runtime sighting tells
        // you it is happening right now. Static wins for remediation.
        ScriptFile | CronEntry | SystemdUnit => 5,
        AuditLog => 4,
        ProcCmdline | ProcEnv => 3,
        HistoryFile => 2,
        ConfigFile => 1,
        Unknown => 0,
    }
}
