//! eBPF collection — outline and tradeoffs, not a dependency.
//!
//! `auditd` is the right default: it needs no build toolchain, its records are
//! plain text, and distros ship rules for it. eBPF is preferable when auditd
//! is not allowed, when the event rate is high enough that auditd becomes the
//! bottleneck, or when you want to filter in the kernel.
//!
//! ## Shape of a minimal collector
//!
//! Attach to `sched_process_exec` (a tracepoint that fires in the context of
//! the exec'ing task, after the new image is installed, so the task's
//! `mm->arg_start`/`mm->arg_end` point at the new argv):
//!
//! ```c
//! // exec.bpf.c
//! #include <linux/bpf.h>
//! #include <bpf/bpf_helpers.h>
//! #include <bpf/bpf_tracing.h>
//!
//! struct event {
//!     __u32 pid, ppid, uid;
//!     __u32 argc;
//!     char  comm[16];
//!     char  argv[4096];   // NUL-joined, bounded
//! };
//!
//! struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 24); }
//!      events SEC(".maps");
//!
//! SEC("tp/sched/sched_process_exec")
//! int on_exec(struct trace_event_raw_sched_process_exec *ctx)
//! {
//!     struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//!     if (!e) return 0;
//!     struct task_struct *t = (void *)bpf_get_current_task();
//!     // bpf_probe_read_user_str over mm->arg_start, bounded by arg_end.
//!     // Reading argv *after* exec is safe here: it is the new image's argv.
//!     ...
//!     bpf_ringbuf_submit(e, 0);
//!     return 0;
//! }
//! char LICENSE[] SEC("license") = "GPL";
//! ```
//!
//! ## Why this is not wired in by default
//!
//! * It needs `clang`, `libbpf`, and a kernel with BTF (≥ 5.8 for the
//!   ring buffer and CO-RE). Adding that to a security tool means it will not
//!   build on the hosts that most need it.
//! * Loading a program needs `CAP_BPF`/`CAP_SYS_ADMIN`, which is the same
//!   privilege auditd needs, so it buys little unless auditd is restricted.
//! * The text form has a hard size ceiling. Long environment dumps are what
//!   matter here, and `bpf_probe_read_user_str` fails past the buffer, so a
//!   truncated capture looks like "no finding".
//!
//! The `ebpf` feature in `Cargo.toml` is intentionally absent. This module
//! documents the design and parses a *stream* of events emitted by a separate
//! collector (JSON lines), so an operator who already runs an eBPF agent can
//! feed it in without this crate depending on a kernel toolchain.

use crate::model::{Finding, LocationRef, ProcessRef, Surface};
use crate::scan::detect::{self, Context};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct BpfEvent {
    pub pid: u32,
    #[serde(default)]
    pub ppid: Option<u32>,
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub comm: Option<String>,
    /// NUL-joined argv, as the agent captured it.
    pub argv: Vec<String>,
    #[serde(default)]
    pub truncated: bool,
}

/// Parse an agent's JSON-lines output. One event per line; a malformed line is
/// skipped rather than aborting the whole feed.
pub fn parse_events(text: &str) -> (Vec<BpfEvent>, usize) {
    let mut out = Vec::new();
    let mut bad = 0;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<BpfEvent>(line) {
            Ok(e) => out.push(e),
            Err(_) => bad += 1,
        }
    }
    (out, bad)
}

pub fn scan_events(events: &[BpfEvent], salt: Option<&str>) -> Vec<Finding> {
    let mut out = Vec::new();
    for e in events {
        if e.argv.is_empty() {
            continue;
        }
        let loc = LocationRef {
            surface: Surface::ProcCmdline,
            display: format!("exec pid {}{}", e.pid, e.comm.as_deref().map(|c| format!(" ({c})")).unwrap_or_default()),
            file: None,
            line: None,
            mode: None,
            owner_uid: e.uid,
        };
        let process = ProcessRef {
            pid: e.pid,
            ppid: e.ppid,
            uid: e.uid,
            comm: e.comm.clone(),
            exe: e.argv.first().cloned(),
            ancestors: Vec::new(),
        };
        let ctx = Context {
            location: loc,
            process: Some(process),
            salt,
        };
        let line = crate::collect::proc::cmdline_to_scan_string(&e.argv);
        let mut f = detect::scan_line(&line, Surface::ProcCmdline, &ctx);
        for f in f.iter_mut() {
            f.notes.push("captured by an eBPF agent at exec".into());
            if e.truncated {
                f.notes.push(
                    "the agent reported a truncated capture; arguments past the buffer were not seen".into(),
                );
            }
        }
        out.extend(f);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const FEED: &str = r#"{"pid":101,"ppid":1,"uid":0,"comm":"mysqldump","argv":["mysqldump","-u","app","-pHunter2Secret","db"]}
not json
{"pid":102,"comm":"redis-cli","argv":["redis-cli","-aOtherSecret9","ping"]}
"#;

    #[test]
    fn parses_stream_and_counts_bad_lines() {
        let (events, bad) = parse_events(FEED);
        assert_eq!(events.len(), 2);
        assert_eq!(bad, 1);
    }

    #[test]
    fn detects_and_masks() {
        let (events, _) = parse_events(FEED);
        let fs = scan_events(&events, None);
        assert_eq!(fs.len(), 2);
        assert!(fs.iter().all(|f| !f.context.contains("Hunter2Secret")));
        assert!(fs.iter().all(|f| !f.context.contains("OtherSecret9")));
        assert_eq!(fs[0].process.as_ref().unwrap().pid, 101);
    }

    #[test]
    fn truncated_capture_is_flagged() {
        let line = r#"{"pid":5,"argv":["mysql","-pHunter2Secret"],"truncated":true}"#;
        let (events, _) = parse_events(line);
        let fs = scan_events(&events, None);
        assert!(fs[0].notes.iter().any(|n| n.contains("truncated")));
    }
}
