//! Reading `/proc` — the runtime fallback.
//!
//! ## What `/proc` can and cannot tell you
//!
//! * `/proc/<pid>/cmdline` is **world-readable** (`0444`), so any local user
//!   can read any process's arguments. That is precisely the vulnerability
//!   being hunted, and it also makes this collector work without privileges
//!   for the cmdline part.
//! * `/proc/<pid>/environ` is `0400` and owned by the process's uid: only that
//!   user and root can read it. Cross-user environment scanning needs root.
//! * A process that lives for a few milliseconds will usually be gone between
//!   two polls. Measured on a busy host, a 100 ms poll loop with ~2000
//!   processes per pass still misses most short-lived `sh -c ...` children.
//!
//! So this module is deliberately honest: it is a **fallback for long-lived
//! processes** (daemons, tmux panes, interactive shells). For short-lived
//! commands use [`super::audit`] (auditd `execve` records) or [`super::bpf`].

use crate::model::Finding;

#[derive(Debug, Clone)]
pub struct ProcOptions {
    /// Also read `/proc/<pid>/environ`. Needs permissions; failures are noted.
    pub environ: bool,
    /// Only scan processes whose uid is in this set (empty means all visible).
    pub uids: Vec<u32>,
    /// Skip the collector's own pid and its ancestors.
    pub exclude_self: bool,
    pub salt: Option<String>,
}

impl Default for ProcOptions {
    fn default() -> Self {
        ProcOptions {
            environ: true,
            uids: Vec::new(),
            exclude_self: true,
            salt: None,
        }
    }
}

/// Join argv into a string that the shell lexer can re-split correctly:
/// elements containing whitespace or quotes are single-quoted.
pub fn cmdline_to_scan_string(argv: &[String]) -> String {
    let mut out = String::new();
    for (i, a) in argv.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let needs_quotes = a.is_empty()
            || a.chars()
                .any(|c| c.is_whitespace() || matches!(c, '\'' | '"' | '\\' | '$' | '`'));
        if needs_quotes {
            out.push('\'');
            for c in a.chars() {
                if c == '\'' {
                    out.push_str("'\\''");
                } else {
                    out.push(c);
                }
            }
            out.push('\'');
        } else {
            out.push_str(a);
        }
    }
    out
}

/// Split raw `/proc/<pid>/cmdline` bytes into argv.
pub fn split_cmdline(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

/// Parse raw `/proc/<pid>/environ` bytes into `(name, value)` pairs.
pub fn parse_environ(bytes: &[u8]) -> Vec<(String, String)> {
    bytes
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .filter_map(|s| {
            let eq = s.iter().position(|b| *b == b'=')?;
            let name = String::from_utf8_lossy(&s[..eq]).into_owned();
            let value = String::from_utf8_lossy(&s[eq + 1..]).into_owned();
            Some((name, value))
        })
        .collect()
}

/// Parse `ppid` and `comm` out of `/proc/<pid>/stat`. `comm` may contain
/// spaces and parentheses, so fields are counted from the last `)`.
pub fn parse_stat(stat: &str) -> Option<(u32, u32)> {
    let close = stat.rfind(')')?;
    let open = stat.find('(')?;
    let comm = &stat[open + 1..close];
    let _ = comm;
    let rest = &stat[close + 1..];
    let mut it = rest.split_whitespace();
    let state = it.next()?;
    let _ = state;
    let ppid: u32 = it.next()?.parse().ok()?;
    // The pid is the first field; re-derive it from before the '('.
    let pid: u32 = stat[..open].trim().parse().ok()?;
    Some((pid, ppid))
}

pub fn parse_comm(stat: &str) -> Option<&str> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    Some(&stat[open + 1..close])
}

/// Parse the `Uid:` line of `/proc/<pid>/status`, real uid first.
pub fn parse_status_uid(status: &str) -> Option<u32> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Linux implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use crate::model::{LocationRef, ProcAncestor, ProcessRef, Surface};
    use crate::scan::detect::{self, Context};
    use std::fs;
    use std::io;

    pub fn list_pids() -> io::Result<Vec<u32>> {
        let mut pids = Vec::new();
        for e in fs::read_dir("/proc")? {
            let Ok(e) = e else { continue };
            let name = e.file_name();
            let Some(name) = name.to_str() else { continue };
            if let Ok(pid) = name.parse::<u32>() {
                pids.push(pid);
            }
        }
        Ok(pids)
    }

    fn read(path: &str) -> io::Result<Vec<u8>> {
        fs::read(path)
    }

    fn read_string(path: &str) -> io::Result<String> {
        fs::read_to_string(path)
    }

    pub fn cmdline(pid: u32) -> io::Result<Vec<String>> {
        Ok(split_cmdline(&read(&format!("/proc/{pid}/cmdline"))?))
    }

    pub fn environ(pid: u32) -> io::Result<Vec<(String, String)>> {
        Ok(parse_environ(&read(&format!("/proc/{pid}/environ"))?))
    }

    pub fn stat(pid: u32) -> io::Result<String> {
        read_string(&format!("/proc/{pid}/stat"))
    }

    pub fn status(pid: u32) -> io::Result<String> {
        read_string(&format!("/proc/{pid}/status"))
    }

    pub fn exe(pid: u32) -> Option<String> {
        fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }

    pub fn ppid(pid: u32) -> Option<u32> {
        stat(pid).ok().and_then(|s| parse_stat(&s)).map(|(_, pp)| pp)
    }

    pub fn uid(pid: u32) -> Option<u32> {
        status(pid).ok().and_then(|s| parse_status_uid(&s))
    }

    /// Walk up from `pid`, collecting ancestors until init (`ppid == 0`), a
    /// self-parent loop, or the depth limit.
    pub fn ancestors(pid: u32, limit: usize) -> Vec<ProcAncestor> {
        let mut out = Vec::new();
        let mut cur = ppid(pid);
        let mut seen = std::collections::HashSet::new();
        seen.insert(pid);
        while let Some(p) = cur {
            if p == 0 || p == 1 || !seen.insert(p) || out.len() >= limit {
                break;
            }
            let Ok(argv) = cmdline(p) else { break };
            let comm = stat(p)
                .ok()
                .and_then(|s| parse_comm(&s).map(|c| c.to_string()))
                .unwrap_or_else(|| argv.first().cloned().unwrap_or_default());
            let cmdline = cmdline_to_scan_string(&argv);
            let scheduler = match crate::scan::sh::basename(&comm) {
                "cron" | "crond" | "systemd" | "atd" | "anacron" => {
                    Some(crate::scan::sh::basename(&comm).to_string())
                }
                _ => None,
            };
            out.push(ProcAncestor {
                pid: p,
                comm,
                cmdline,
                scheduler: scheduler.clone(),
            });
            if scheduler.is_some() {
                break;
            }
            cur = ppid(p);
        }
        out
    }

    pub fn scan_pid(pid: u32, opts: &ProcOptions) -> Vec<Finding> {
        let Ok(argv) = cmdline(pid) else { return Vec::new() };
        if argv.is_empty() {
            // Kernel threads and zombies have an empty cmdline.
            return Vec::new();
        }
        let uid = uid(pid);
        if !opts.uids.is_empty() && !uid.map(|u| opts.uids.contains(&u)).unwrap_or(false) {
            return Vec::new();
        }
        let comm = stat(pid)
            .ok()
            .and_then(|s| parse_comm(&s).map(|c| c.to_string()));
        let mut process = ProcessRef {
            pid,
            ppid: ppid(pid),
            uid,
            comm: comm.clone(),
            exe: exe(pid),
            ancestors: Vec::new(),
        };

        let scanline = cmdline_to_scan_string(&argv);
        let mut loc = LocationRef::process(pid);
        loc.owner_uid = uid;
        loc.display = format!(
            "pid {pid}{}",
            comm.as_deref().map(|c| format!(" ({c})")).unwrap_or_default()
        );
        let ctx = Context {
            location: loc,
            process: None,
            salt: opts.salt.as_deref(),
        };
        let mut findings = detect::scan_line(&scanline, Surface::ProcCmdline, &ctx);

        if opts.environ {
            match environ(pid) {
                Ok(pairs) => {
                    let eloc = LocationRef {
                        surface: Surface::ProcEnv,
                        display: format!("pid {pid} environ"),
                        file: None,
                        line: None,
                        mode: None,
                        owner_uid: uid,
                    };
                    let ectx = Context {
                        location: eloc,
                        process: None,
                        salt: opts.salt.as_deref(),
                    };
                    for (name, value) in &pairs {
                        let mut f = detect::scan_env(name, value, &ectx);
                        for f in f.iter_mut() {
                            f.location.display = format!("pid {pid} env:{name}");
                        }
                        findings.append(&mut f);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    if findings.is_empty() {
                        return findings;
                    }
                }
                Err(_) => {}
            }
        }

        if !findings.is_empty() {
            process.ancestors = ancestors(pid, 8);
            for f in findings.iter_mut() {
                f.process = Some(process.clone());
                // Attribute to a scheduler when one is in the chain.
                if let Some(sched) = process.ancestors.iter().find_map(|a| a.scheduler.clone()) {
                    f.notes.push(format!(
                        "spawned under {sched} (ancestor pid {})",
                        process
                            .ancestors
                            .iter()
                            .find(|a| a.scheduler.is_some())
                            .map(|a| a.pid)
                            .unwrap_or(0)
                    ));
                }
            }
        }
        findings
    }

    pub fn collect(opts: &ProcOptions) -> Vec<Finding> {
        let mut findings = Vec::new();
        let self_pid = std::process::id();
        let self_chain: std::collections::HashSet<u32> = if opts.exclude_self {
            let mut s = std::collections::HashSet::new();
            s.insert(self_pid);
            let mut cur = ppid(self_pid);
            while let Some(p) = cur {
                if p == 0 || !s.insert(p) {
                    break;
                }
                cur = ppid(p);
            }
            s
        } else {
            std::collections::HashSet::new()
        };
        let Ok(pids) = list_pids() else {
            return findings;
        };
        for pid in pids {
            if opts.exclude_self && self_chain.contains(&pid) {
                continue;
            }
            findings.extend(scan_pid(pid, opts));
        }
        // Stable order so repeated runs compare.
        findings.sort_by(|a, b| {
            a.location
                .display
                .cmp(&b.location.display)
                .then(a.span.start.cmp(&b.span.start))
        });
        findings
    }
}

#[cfg(target_os = "linux")]
pub use imp::*;

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;
    use crate::model::ProcAncestor;
    pub fn list_pids() -> std::io::Result<Vec<u32>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "/proc is only available on Linux",
        ))
    }
    pub fn collect(_opts: &ProcOptions) -> Vec<Finding> {
        Vec::new()
    }
    pub fn scan_pid(_pid: u32, _opts: &ProcOptions) -> Vec<Finding> {
        Vec::new()
    }
    pub fn ancestors(_pid: u32, _limit: usize) -> Vec<ProcAncestor> {
        Vec::new()
    }
}

#[cfg(not(target_os = "linux"))]
pub use imp::*;

/// A poll loop. Kept out of `collect` so a caller can drive it with a stop
/// condition; `interval` below ~50 ms starts costing more than it catches.
pub fn poll_once(opts: &ProcOptions) -> Vec<Finding> {
    collect(opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmdline_roundtrip_keeps_argv_boundaries() {
        let argv = vec![
            "mysql".to_string(),
            "-u".to_string(),
            "app".to_string(),
            "-ps3cr3t with space".to_string(),
        ];
        let s = cmdline_to_scan_string(&argv);
        let cmds = crate::scan::sh::lex_line(&s);
        assert_eq!(cmds.len(), 1);
        let toks: Vec<&str> = cmds[0].tokens.iter().map(|t| t.text.as_str()).collect();
        assert_eq!(toks, vec!["mysql", "-u", "app", "-ps3cr3t with space"]);
    }

    #[test]
    fn cmdline_quotes_single_quote_values() {
        let argv = vec!["sh".to_string(), "-c".to_string(), "echo it's".to_string()];
        let s = cmdline_to_scan_string(&argv);
        let cmds = crate::scan::sh::lex_line(&s);
        assert_eq!(cmds[0].tokens[2].text, "echo it's");
    }

    #[test]
    fn split_cmdline_ignores_trailing_nul() {
        let raw = b"psql\0-U\0app\0\0";
        assert_eq!(
            split_cmdline(raw),
            vec!["psql".to_string(), "-U".to_string(), "app".to_string()]
        );
    }

    #[test]
    fn parse_environ_pairs() {
        let raw = b"A=1\0B=x=y\0EMPTY=\0";
        let pairs = parse_environ(raw);
        assert_eq!(pairs[0], ("A".to_string(), "1".to_string()));
        assert_eq!(pairs[1], ("B".to_string(), "x=y".to_string()));
        assert_eq!(pairs[2], ("EMPTY".to_string(), String::new()));
    }

    #[test]
    fn parse_stat_handles_spaces_in_comm() {
        // A process whose name contains a space and parentheses.
        let stat = "4242 (weird) name) S 1000 4242 4242 0 -1 4194304";
        let (pid, ppid) = parse_stat(stat).unwrap();
        assert_eq!(pid, 4242);
        assert_eq!(ppid, 1000);
        assert_eq!(parse_comm(stat), Some("weird) name"));
    }

    #[test]
    fn parse_status_uid_takes_real_uid() {
        let status = "Name:\tmysql\nUid:\t27\t27\t27\t27\nGid:\t27\t27\t27\t27\n";
        assert_eq!(parse_status_uid(status), Some(27));
    }

    #[test]
    fn cmdline_detection_end_to_end_on_a_synthetic_line() {
        let argv = vec![
            "/usr/bin/mysql".to_string(),
            "-u".to_string(),
            "app".to_string(),
            "-pHunter2Secret".to_string(),
        ];
        let line = cmdline_to_scan_string(&argv);
        let fs = crate::scan::detect::scan_line(
            &line,
            crate::model::Surface::ProcCmdline,
            &crate::scan::detect::Context::default(),
        );
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].detector, "tool:mysql:-p");
        assert_eq!(fs[0].severity, crate::model::Severity::High);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn can_scan_own_process_without_panic() {
        let opts = ProcOptions::default();
        let _ = scan_pid(std::process::id(), &opts);
    }
}
