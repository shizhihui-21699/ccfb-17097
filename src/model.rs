//! Core data model: findings, their provenance, and nothing secret.
//!
//! Design rule enforced by this module: a [`Finding`] never contains a
//! recoverable credential. It carries a short masked preview, a salted
//! fingerprint for cross-host correlation, and a redacted context line.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" | "med" => Severity::Medium,
            "high" => Severity::High,
            "critical" | "crit" => Severity::Critical,
            _ => return None,
        })
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
    Certain,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
            Confidence::Certain => "certain",
        })
    }
}

/// Where a piece of text was observed. The surface decides who can see it,
/// which decides how bad a leak is, and which "safe" idioms actually apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    /// `/proc/<pid>/cmdline` of a live or recently dead process.
    ProcCmdline,
    /// `/proc/<pid>/environ`.
    ProcEnv,
    /// A shell history file (`.bash_history`, `.zsh_history`, ...).
    HistoryFile,
    /// A shell script or any other file that is executed.
    ScriptFile,
    /// A line of a crontab.
    CronEntry,
    /// An `ExecStart=`, `Environment=` or similar line in a systemd unit.
    SystemdUnit,
    /// An auditd `EXECVE`/`PROCTITLE` record.
    AuditLog,
    /// A static config file that is read at runtime (`.my.cnf`, `.pgpass`, ...).
    ConfigFile,
    #[default]
    Unknown,
}

impl Surface {
    pub fn is_runtime(&self) -> bool {
        matches!(
            self,
            Surface::ProcCmdline | Surface::ProcEnv | Surface::AuditLog
        )
    }

    /// Text seen at exec time has already been expanded by the shell, so a
    /// `$VAR` there is the *literal* value of a variable that was expanded to
    /// this string. Reference-looking text is therefore not a defence.
    pub fn is_expanded(&self) -> bool {
        self.is_runtime()
    }

    pub fn label(&self) -> &'static str {
        match self {
            Surface::ProcCmdline => "process cmdline",
            Surface::ProcEnv => "process environ",
            Surface::HistoryFile => "shell history",
            Surface::ScriptFile => "script",
            Surface::CronEntry => "cron",
            Surface::SystemdUnit => "systemd unit",
            Surface::AuditLog => "audit log",
            Surface::ConfigFile => "config file",
            Surface::Unknown => "unknown",
        }
    }

    /// Who can read this text, given default permissions on a Linux host.
    pub fn exposure(&self) -> Exposure {
        match self {
            Surface::ProcCmdline => Exposure::WorldReadable,
            Surface::ProcEnv => Exposure::OwnerAndRoot,
            // The audit log itself is root-only, but the record is a durable
            // copy of a value that was world-readable at exec time, so the
            // finding keeps the cmdline severity. The exposure label is only
            // used for reporting.
            Surface::AuditLog => Exposure::RootOnly,
            Surface::HistoryFile | Surface::ScriptFile | Surface::ConfigFile => {
                Exposure::FilePermissions
            }
            Surface::CronEntry | Surface::SystemdUnit => Exposure::FilePermissions,
            Surface::Unknown => Exposure::FilePermissions,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exposure {
    WorldReadable,
    OwnerAndRoot,
    RootOnly,
    FilePermissions,
}

impl Exposure {
    pub fn label(&self) -> &'static str {
        match self {
            Exposure::WorldReadable => "world-readable",
            Exposure::OwnerAndRoot => "readable by owner and root",
            Exposure::RootOnly => "root-readable",
            Exposure::FilePermissions => "file permissions",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Password,
    Passphrase,
    ApiKey,
    Token,
    SessionToken,
    AccessKeyId,
    SecretAccessKey,
    PrivateKey,
    ConnectionString,
    OpaqueCredential,
}

impl SecretKind {
    pub fn label(&self) -> &'static str {
        match self {
            SecretKind::Password => "password",
            SecretKind::Passphrase => "passphrase",
            SecretKind::ApiKey => "API key",
            SecretKind::Token => "token",
            SecretKind::SessionToken => "session token",
            SecretKind::AccessKeyId => "access key id",
            SecretKind::SecretAccessKey => "secret access key",
            SecretKind::PrivateKey => "private key",
            SecretKind::ConnectionString => "connection string with password",
            SecretKind::OpaqueCredential => "credential",
        }
    }
}

/// The replacement channel proposed for a leaked credential, ordered from
/// safest to least safe. The ordering is the migration policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    /// Ask the protected store for it inside the wrapper, never putting it in
    /// any argv or env of the target.
    Fd,
    Stdin,
    /// Env is readable only by the owner and root, never by other users.
    Env,
    /// A 0600 file that the tool reads itself (config file, `--defaults-file`).
    ProtectedFile,
    /// Tool-native mechanism that hides the value (e.g. `curl --config -`).
    ToolConfigFile,
    /// The tool accepts the credential only in argv. There is no way to hide
    /// it from a process that reads its own argv, so the real fix is to make
    /// `/proc` unreadable to other users (`hidepid=2` / `ProtectProc=`), run
    /// the job as a dedicated uid, and at least keep the value out of static
    /// files and history by injecting it at exec time.
    ArgvOnly,
    /// Not a leak at all (already a reference, or a placeholder).
    None,
}

impl Channel {
    pub fn label(&self) -> &'static str {
        match self {
            Channel::Fd => "file descriptor",
            Channel::Stdin => "stdin",
            Channel::Env => "environment",
            Channel::ProtectedFile => "protected file",
            Channel::ToolConfigFile => "tool config stream",
            Channel::ArgvOnly => "argv (unavoidable)",
            Channel::None => "none",
        }
    }

    pub fn exposure(&self) -> &'static str {
        match self {
            Channel::Fd => "never leaves the wrapper",
            Channel::Stdin => "never leaves the wrapper",
            Channel::Env => "owner and root only",
            Channel::ProtectedFile => "file mode 0600",
            Channel::ToolConfigFile => "never leaves the wrapper",
            Channel::ArgvOnly => "readable per /proc mount options (use hidepid=2)",
            Channel::None => "-",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remediation {
    pub channel: Channel,
    /// One-line description of what the tool can be told to do instead.
    pub action: String,
    /// Copy-pasteable replacement for the leaking fragment.
    pub snippet: String,
    pub caveats: Vec<String>,
    /// What is still exposed after applying the fix.
    pub residual: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Span { start, end }
    }
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn contains(&self, other: Span) -> bool {
        self.start <= other.start && other.end <= self.end
    }
}

/// A process tree position, used to attribute a cmdline finding to the shell,
/// cron job or unit that spawned it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessRef {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub uid: Option<u32>,
    pub comm: Option<String>,
    pub exe: Option<String>,
    /// Ancestor chain, nearest first, up to the init/cron/systemd boundary.
    pub ancestors: Vec<ProcAncestor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcAncestor {
    pub pid: u32,
    pub comm: String,
    pub cmdline: String,
    /// Set when the ancestor is a known scheduler (`cron`, `systemd`, `atd`).
    pub scheduler: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocationRef {
    pub surface: Surface,
    /// Human readable, e.g. `/etc/cron.d/backup:3` or `pid 1234`.
    pub display: String,
    /// File path when the surface is file-backed.
    pub file: Option<String>,
    pub line: Option<u32>,
    /// File mode when known (permission-based severity).
    pub mode: Option<u32>,
    /// Owner uid when known.
    pub owner_uid: Option<u32>,
}

impl LocationRef {
    pub fn file(surface: Surface, path: &str, line: u32, mode: Option<u32>) -> Self {
        LocationRef {
            surface,
            display: format!("{path}:{line}"),
            file: Some(path.to_string()),
            line: Some(line),
            mode,
            owner_uid: None,
        }
    }

    pub fn process(pid: u32) -> Self {
        LocationRef {
            surface: Surface::ProcCmdline,
            display: format!("pid {pid}"),
            file: None,
            line: None,
            mode: None,
            owner_uid: None,
        }
    }

    /// True when the containing file is readable by users other than its owner.
    pub fn world_readable(&self) -> bool {
        match self.mode {
            Some(m) => m & 0o004 != 0,
            None => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub confidence: Confidence,
    pub kind: SecretKind,
    pub provider: Option<String>,
    /// Stable identifier of the detector that fired, e.g. `tool:mysql:password`.
    pub detector: String,
    pub location: LocationRef,
    pub process: Option<ProcessRef>,
    pub program: Option<String>,
    /// Flag, env var name or config key that carried the value.
    pub key: Option<String>,
    pub span: Span,
    /// Masked preview. Never enough to recover the value.
    pub preview: String,
    /// `sha256(domain || salt || value)` truncated; correlates occurrences
    /// without storing or revealing the value.
    pub fingerprint: String,
    pub value_len: usize,
    /// The whole line with every detected value replaced by `***`.
    pub context: String,
    pub remediation: Option<Remediation>,
    pub notes: Vec<String>,
    /// Set when the finding is in a file whose permissions already limit
    /// exposure, or when the finding is a reference rather than a secret.
    pub suppressed: bool,
}

impl Finding {
    pub fn dedup_key(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.fingerprint,
            self.location.display,
            self.key.as_deref().unwrap_or(""),
            self.location.surface as u8
        )
    }

    pub fn is_actionable(&self) -> bool {
        !self.suppressed && self.severity >= Severity::Low
    }
}

/// Salted, truncated fingerprint. The salt is per-deployment so fingerprints
/// cannot be reversed with a precomputed table of common passwords.
pub fn fingerprint(value: &str, salt: Option<&str>) -> String {
    let mut h = Sha256::new();
    h.update(b"credops-fp-v1\0");
    h.update(salt.unwrap_or("").as_bytes());
    h.update(b"\0");
    h.update(value.as_bytes());
    let digest = h.finalize();
    let mut out = String::with_capacity(16);
    for b in digest.iter().take(8) {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Masked preview: at most two leading and two trailing characters, and only
/// for values long enough that those characters do not give the value away.
pub fn preview(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    match chars.len() {
        0 => "<empty>".to_string(),
        1..=5 => "******".to_string(),
        6..=9 => {
            let head: String = chars.iter().take(1).collect();
            format!("{head}****** ({} chars)", chars.len())
        }
        10..=15 => {
            let head: String = chars.iter().take(2).collect();
            let tail: String = chars[chars.len() - 2..].iter().collect();
            format!("{head}******{tail} ({} chars)", chars.len())
        }
        _ => {
            // Long values: first 4 / last 4 leaks little and helps operators
            // recognise which credential it is.
            let head: String = chars.iter().take(4).collect();
            let tail: String = chars[chars.len() - 4..].iter().collect();
            format!("{head}******{tail} ({} chars)", chars.len())
        }
    }
}

/// Replace every span with a fixed mask, right to left so offsets stay valid.
pub fn redact_spans(raw: &str, spans: &[Span]) -> String {
    let mut ordered: Vec<Span> = spans.to_vec();
    ordered.sort_by_key(|s| s.start);
    let mut out = String::with_capacity(raw.len());
    let mut cursor = 0usize;
    for span in ordered {
        if span.start < cursor || span.end > raw.len() {
            continue;
        }
        if !raw.is_char_boundary(span.start) || !raw.is_char_boundary(span.end) {
            continue;
        }
        out.push_str(&raw[cursor..span.start]);
        out.push_str("***");
        cursor = span.end;
    }
    out.push_str(&raw[cursor..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_salted_and_stable() {
        let a = fingerprint("hunter2", None);
        let b = fingerprint("hunter2", None);
        let c = fingerprint("hunter2", Some("salt"));
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 16);
        assert!(!a.contains("hunter"));
    }

    #[test]
    fn preview_hides_short_values_entirely() {
        assert_eq!(preview("abc"), "******");
        assert_eq!(preview("abcdef"), "a****** (6 chars)");
        let p = preview("supersecretpassword123");
        assert!(p.contains("******"));
        assert!(!p.contains("secretpassword"));
    }

    #[test]
    fn redaction_is_offset_safe() {
        let raw = "mysql -u app -pHunter2 --host db";
        let start = raw.find("Hunter2").unwrap();
        let out = redact_spans(raw, &[Span::new(start, start + 7)]);
        assert_eq!(out, "mysql -u app -p*** --host db");
        // out-of-range spans are ignored, never panicking
        let out2 = redact_spans(raw, &[Span::new(900, 999)]);
        assert_eq!(out2, raw);
    }
}
