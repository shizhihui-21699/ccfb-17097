//! auditd `execve` records — the reliable way to see short-lived processes.
//!
//! The kernel writes a record at every `execve`, so there is no sampling and
//! no missed process. A typical rule:
//!
//! ```text
//! -a always,exit -F arch=b64 -S execve -F uid>=1000 -k credops
//! ```
//!
//! The same event arrives as several records sharing `audit(1699999999.123:456)`:
//!
//! ```text
//! type=SYSCALL msg=audit(1699999999.123:456): arch=c000003e syscall=59 ... exe="/usr/bin/mysql" uid=1000 ...
//! type=EXECVE msg=audit(1699999999.123:456): argc=4 a0="mysql" a1="-u" a2="app" a3="-pHunter2Secret" a4="db"
//! type=PROCTITLE msg=audit(1699999999.123:456): proctitle=6D7973716C002D7500617070002D7048...
//! ```
//!
//! Two parsing details matter:
//!
//! * `a0`, `a1`, ... are quoted, may contain escaped `\"` and `\\`, and long
//!   values are split into `a1_len=NNNN a1[0]=... a1[1]=...` chunks.
//! * `proctitle` is a hex encoding of the NUL-joined argv. It is the only
//!   field that keeps real NUL boundaries, so it is preferred when present.

use crate::model::{Finding, LocationRef, Surface};
use crate::scan::detect::{self, Context};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
pub struct Event {
    pub id: String,
    pub timestamp: Option<f64>,
    pub serial: Option<u64>,
    pub exe: Option<String>,
    pub uid: Option<u32>,
    pub ppid: Option<u32>,
    pub pid: Option<u32>,
    pub comm: Option<String>,
    pub cwd: Option<String>,
    pub argc: Option<usize>,
    /// Reconstructed argv, or `None` when the record was truncated.
    pub argv: Option<Vec<String>>,
    pub truncated: bool,
}

/// Parse the `audit(1699999999.123:456)` identifier.
pub fn parse_id(line: &str) -> Option<String> {
    let start = line.find("audit(")? + "audit(".len();
    let end = line[start..].find(')')? + start;
    Some(line[start..end].to_string())
}

fn field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let pat = format!(" {name}=");
    let idx = line.find(&pat)? + pat.len();
    let rest = &line[idx..];
    if let Some(stripped) = rest.strip_prefix('"') {
        let mut out_end = None;
        let bytes = stripped.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\\' {
                i += 2;
                continue;
            }
            if bytes[i] == b'"' {
                out_end = Some(i);
                break;
            }
            i += 1;
        }
        Some(&stripped[..out_end?])
    } else {
        let end = rest.find(' ').unwrap_or(rest.len());
        Some(&rest[..end])
    }
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let val = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut i = 0;
    while i < b.len() {
        out.push((val(b[i])? << 4) | val(b[i + 1])?);
        i += 2;
    }
    Some(out)
}

/// Parse a whole audit log, grouping records by event id.
pub fn parse_log(text: &str) -> Vec<Event> {
    let mut events: BTreeMap<String, Event> = BTreeMap::new();
    for line in text.lines() {
        let Some(id) = parse_id(line) else { continue };
        let e = events.entry(id.clone()).or_insert_with(|| Event {
            id: id.clone(),
            ..Default::default()
        });
        if let Some(ts) = id.split(':').next().and_then(|s| s.parse().ok()) {
            e.timestamp = Some(ts);
        }
        if let Some(serial) = id.split(':').nth(1).and_then(|s| s.parse().ok()) {
            e.serial = Some(serial);
        }
        if line.starts_with("type=EXECVE") {
            parse_execve(line, e);
        } else if line.starts_with("type=PROCTITLE") {
            parse_proctitle(line, e);
        } else if line.starts_with("type=SYSCALL") {
            e.exe = field(line, "exe").map(unescape);
            e.uid = field(line, "uid").and_then(|v| v.parse().ok());
            e.ppid = field(line, "ppid").and_then(|v| v.parse().ok());
            e.pid = field(line, "pid").and_then(|v| v.parse().ok());
            e.comm = field(line, "comm").map(unescape);
            e.cwd = field(line, "cwd").map(unescape);
        }
    }
    events.into_values().collect()
}

/// A field scanner that respects double quotes. Audit uses `key=value` and
/// `key="value"`; a quoted value may contain spaces and escaped quotes, so
/// splitting on whitespace is wrong for anything but the simplest records.
struct Fields<'a> {
    line: &'a str,
}

impl<'a> Fields<'a> {
    fn tokens(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let b = self.line.as_bytes();
        let mut i = 0;
        while i < b.len() {
            while i < b.len() && (b[i] == b' ') {
                i += 1;
            }
            if i >= b.len() {
                break;
            }
            let key_start = i;
            while i < b.len() && b[i] != b'=' && b[i] != b' ' {
                i += 1;
            }
            if i >= b.len() || b[i] == b' ' {
                // Bare token with no value.
                i += 1;
                continue;
            }
            let key = &self.line[key_start..i];
            i += 1; // '='
            let mut val = String::new();
            if i < b.len() && b[i] == b'"' {
                i += 1;
                while i < b.len() {
                    if b[i] == b'\\' && i + 1 < b.len() {
                        val.push(b[i] as char);
                        val.push(b[i + 1] as char);
                        i += 2;
                        continue;
                    }
                    if b[i] == b'"' {
                        i += 1;
                        break;
                    }
                    // Copy a whole UTF-8 scalar is unnecessary: audit values
                    // are ASCII or hex; non-ASCII comes through proctitle.
                    val.push(b[i] as char);
                    i += 1;
                }
            } else {
                let v_start = i;
                while i < b.len() && b[i] != b' ' {
                    i += 1;
                }
                val.push_str(&self.line[v_start..i]);
            }
            out.push((key.to_string(), val));
        }
        out
    }
}

fn parse_execve(line: &str, e: &mut Event) {
    let fields = Fields { line }.tokens();
    let mut named: BTreeMap<usize, String> = BTreeMap::new();
    let mut chunks: BTreeMap<(usize, usize), String> = BTreeMap::new();
    for (key, val) in fields {
        if key == "argc" {
            e.argc = val.parse().ok();
        } else if let Some(rest) = key.strip_prefix('a') {
            if let Some(bracket) = rest.find('[') {
                let idx: Option<usize> = rest[..bracket].parse().ok();
                let chunk_idx: Option<usize> = rest[bracket + 1..]
                    .trim_end_matches(']')
                    .parse()
                    .ok();
                if let (Some(idx), Some(ci)) = (idx, chunk_idx) {
                    chunks.insert((idx, ci), unescape(&val));
                }
            } else if let Ok(idx) = rest.parse::<usize>() {
                named.insert(idx, unescape(&val));
            }
        }
    }
    if !chunks.is_empty() {
        let mut assembled: BTreeMap<usize, String> = BTreeMap::new();
        for ((idx, _ci), v) in chunks {
            assembled.entry(idx).or_default().push_str(&v);
        }
        named.extend(assembled);
    }
    if named.is_empty() {
        return;
    }
    let n = *named.keys().next_back().unwrap() + 1;
    let mut argv = Vec::with_capacity(n);
    for i in 0..n {
        match named.get(&i) {
            Some(v) => argv.push(v.clone()),
            None => {
                // A hole cannot be reconstructed; a partial argv would put
                // arguments at the wrong positions.
                e.truncated = true;
                e.argv = None;
                return;
            }
        }
    }
    if let Some(argc) = e.argc {
        if argc != argv.len() {
            e.truncated = true;
        }
    }
    e.argv = Some(argv);
}

fn parse_proctitle(line: &str, e: &mut Event) {
    let Some(hex) = field(line, "proctitle") else { return };
    let Some(bytes) = unhex(hex) else { return };
    let argv: Vec<String> = bytes
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    if !argv.is_empty() {
        e.argv = Some(argv);
        e.truncated = false;
    }
}

/// Turn a parsed event into findings, attributing it to the exe that ran.
pub fn scan_event(e: &Event, salt: Option<&str>) -> Vec<Finding> {
    let Some(argv) = &e.argv else {
        // Truncated EXECVE without PROCTITLE: we know the program but not the
        // arguments, which is exactly the case we cannot assert on.
        return Vec::new();
    };
    if argv.is_empty() {
        return Vec::new();
    }
    let display = match (e.pid, e.timestamp) {
        (Some(pid), Some(ts)) => format!("audit pid {pid} @{ts:.3}"),
        (Some(pid), None) => format!("audit pid {pid}"),
        _ => format!("audit event {}", e.id),
    };
    let loc = LocationRef {
        surface: Surface::AuditLog,
        display,
        file: e.cwd.clone(),
        line: None,
        mode: None,
        owner_uid: e.uid,
    };
    let process = crate::model::ProcessRef {
        pid: e.pid.unwrap_or(0),
        ppid: e.ppid,
        uid: e.uid,
        comm: e.comm.clone(),
        exe: e.exe.clone(),
        ancestors: Vec::new(),
    };
    let ctx = Context {
        location: loc,
        process: Some(process),
        salt,
    };
    let line = crate::collect::proc::cmdline_to_scan_string(argv);
    let mut findings = detect::scan_line(&line, Surface::AuditLog, &ctx);
    for f in findings.iter_mut() {
        if let Some(exe) = &e.exe {
            f.notes.push(format!("executable: {exe}"));
        }
        if let Some(cwd) = &e.cwd {
            f.notes.push(format!("working directory: {cwd}"));
        }
        f.notes.push(
            "captured by the kernel at execve, so the process may already have exited".into(),
        );
    }
    findings
}

pub fn scan_log(text: &str, salt: Option<&str>) -> Vec<Finding> {
    let mut out = Vec::new();
    for e in parse_log(text) {
        out.extend(scan_event(&e, salt));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    const SIMPLE: &str = r#"type=SYSCALL msg=audit(1699999999.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=55d0 a1=55e0 a2=55f0 a3=8 items=2 ppid=1000 pid=4242 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 comm="mysql" exe="/usr/bin/mysql" key="credops"
type=EXECVE msg=audit(1699999999.123:456): argc=5 a0="mysql" a1="-u" a2="app" a3="-pHunter2Secret" a4="mydb"
type=PROCTITLE msg=audit(1699999999.123:456): proctitle=6D7973716C002D7500617070002D7048756E74657232536563726574006D796462
"#;

    #[test]
    fn parses_syscall_execve_proctitle() {
        let events = parse_log(SIMPLE);
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.pid, Some(4242));
        assert_eq!(e.uid, Some(1000));
        assert_eq!(e.exe.as_deref(), Some("/usr/bin/mysql"));
        assert_eq!(
            e.argv.as_ref().unwrap(),
            &vec!["mysql", "-u", "app", "-pHunter2Secret", "mydb"]
        );
    }

    #[test]
    fn proctitle_hex_split_is_preferred() {
        let events = parse_log(SIMPLE);
        let argv = events[0].argv.as_ref().unwrap();
        assert_eq!(argv[3], "-pHunter2Secret");
    }

    #[test]
    fn detects_password_in_audit_event() {
        let fs = scan_log(SIMPLE, None);
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].detector, "tool:mysql:-p");
        assert_eq!(fs[0].severity, Severity::High);
        assert_eq!(fs[0].location.surface, Surface::AuditLog);
        assert!(fs[0].process.as_ref().unwrap().pid == 4242);
        assert!(!fs[0].context.contains("Hunter2Secret"));
    }

    #[test]
    fn escaped_quotes_in_args() {
        let line = r#"type=EXECVE msg=audit(1.0:1): argc=3 a0="sh" a1="-c" a2="echo \"x\" \\ done""#;
        let events = parse_log(line);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].argv.as_ref().unwrap()[2], r#"echo "x" \ done"#);
        assert_eq!(events[0].argc, Some(3));
    }

    #[test]
    fn chunked_long_argument() {
        let line = concat!(
            r#"type=EXECVE msg=audit(2.0:2): argc=3 a0="mysql" a1="-u" a2_len=12 a2[0]="Hunter2Sec" a2[1]="retValue" "#,
            "\n"
        );
        let events = parse_log(line);
        assert_eq!(events[0].argv.as_ref().unwrap()[2], "Hunter2SecretValue");
    }

    #[test]
    fn truncated_execve_without_proctitle_yields_nothing() {
        // a2 is missing entirely: we cannot know the password, so we must not
        // invent it.
        let line = r#"type=EXECVE msg=audit(3.0:3): argc=4 a0="mysql" a1="-u" a3="db""#;
        let events = parse_log(line);
        assert!(events[0].truncated);
        assert!(events[0].argv.is_none());
        assert!(scan_log(line, None).is_empty());
    }

    #[test]
    fn hex_decoding() {
        assert_eq!(unhex("6D7973716C").unwrap(), b"mysql");
        assert!(unhex("xyz").is_none());
    }

    #[test]
    fn unquoted_numeric_fields() {
        assert_eq!(field("a uid=1000 b", "uid"), Some("1000"));
        assert_eq!(field("a comm=\"my procs\" b", "comm"), Some("my procs"));
    }

    #[test]
    fn multiple_events_are_separated() {
        let log = format!(
            "{}\n{}",
            r#"type=EXECVE msg=audit(1.0:1): argc=2 a0="redis-cli" a1="-aOtherSecret9""#,
            r#"type=EXECVE msg=audit(1.1:2): argc=2 a0="mysql" a1="-pHunter2Secret""#
        );
        let events = parse_log(&log);
        assert_eq!(events.len(), 2);
        let fs = scan_log(&log, None);
        assert_eq!(fs.len(), 2);
    }
}
