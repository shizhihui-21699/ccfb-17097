//! Static file collection: shell scripts, crontabs, systemd units, history and
//! tool config files.
//!
//! Everything here is pure Rust over `&str` plus a walker, so it runs and is
//! tested on any platform. The Linux-only part (reading `/etc`, `/home`, ...)
//! is the caller's choice of roots.

use crate::model::{Finding, LocationRef, Surface};
use crate::scan::detect::{self, Context};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct FileScanOptions {
    /// Skip files larger than this. A 2 GiB log is not a script.
    pub max_bytes: u64,
    /// Salt for fingerprints.
    pub salt: Option<String>,
}

#[allow(clippy::should_implement_trait)]
impl FileScanOptions {
    pub fn default() -> Self {
        FileScanOptions {
            max_bytes: 4 * 1024 * 1024,
            salt: None,
        }
    }
}

/// Result of looking at one file.
#[derive(Debug, Default)]
pub struct FileScan {
    pub findings: Vec<Finding>,
    pub skipped: Vec<String>,
    pub files_scanned: usize,
}

/// Which line-based syntax a file is scanned as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syntax {
    /// `#` comments, backslash continuation.
    Shell,
    /// Each line is a cron entry (5+ fields) or an env assignment.
    Crontab,
    /// `ExecStart=`, `Environment=` lines inside a unit file.
    SystemdUnit,
    /// `export NAME=value`, plain `NAME=value`, `set` builtins.
    History,
    /// `key = value` or `key: value`, `#`/`;` comments (ini, .my.cnf, .pgpass).
    Config,
}

impl Syntax {
    pub fn from_path(p: &Path) -> Syntax {
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if name.ends_with(".sh")
            || name.ends_with(".bash")
            || name.ends_with(".zsh")
            || name == "sh"
            || name == "bash"
        {
            return Syntax::Shell;
        }
        if p.extension().and_then(|e| e.to_str()) == Some("service")
            || p.extension().and_then(|e| e.to_str()) == Some("timer")
            || p.extension().and_then(|e| e.to_str()) == Some("socket")
            || name.ends_with(".service.d")
        {
            return Syntax::SystemdUnit;
        }
        if matches!(name, ".my.cnf" | ".pgpass" | ".netrc" | ".curlrc" | "credentials")
            || p.extension().and_then(|e| e.to_str()) == Some("cnf")
            || p.extension().and_then(|e| e.to_str()) == Some("ini")
            || p.extension().and_then(|e| e.to_str()) == Some("conf")
        {
            return Syntax::Config;
        }
        if name.ends_with("_history") || name == ".bash_history" || name == ".zsh_history" {
            return Syntax::History;
        }
        let lower = name.to_ascii_lowercase();
        if lower.starts_with("crontab") || lower.ends_with(".cron") {
            return Syntax::Crontab;
        }
        Syntax::Shell
    }
}

/// Read a file, scan it, and attach file mode so severity reflects exposure.
pub fn scan_file(path: &Path, syntax: Syntax, opts: &FileScanOptions) -> anyhow::Result<FileScan> {
    let meta = fs::metadata(path)?;
    let mut out = FileScan::default();
    if !meta.is_file() {
        return Ok(out);
    }
    if meta.len() > opts.max_bytes {
        out.skipped.push(format!(
            "{}: {} bytes exceeds limit",
            path.display(),
            meta.len()
        ));
        return Ok(out);
    }
    let bytes = fs::read(path)?;
    // Scripts are text; if it is not valid UTF-8 do not guess.
    let Ok(text) = String::from_utf8(bytes) else {
        out.skipped.push(format!("{}: not UTF-8", path.display()));
        return Ok(out);
    };
    out.files_scanned = 1;
    let mode = Some(meta.mode() & 0o7777);
    out.findings = scan_text(&text, path, syntax, mode, opts.salt.as_deref());
    for f in out.findings.iter_mut() {
        f.location.owner_uid = Some(meta.uid());
    }
    Ok(out)
}

/// Scan already-loaded text. Separated out so tests need no filesystem.
pub fn scan_text(
    text: &str,
    path: &Path,
    syntax: Syntax,
    mode: Option<u32>,
    salt: Option<&str>,
) -> Vec<Finding> {
    let display = path.display().to_string();
    let mut findings = Vec::new();

    match syntax {
        Syntax::Shell => {
            for (idx, unit) in logical_lines(text).iter().enumerate() {
                let surface = Surface::ScriptFile;
                let loc = LocationRef::file(surface, &display, unit.line, mode);
                let ctx = Context {
                    location: loc,
                    process: None,
                    salt,
                };
                let mut f = detect::scan_line(&unit.text, surface, &ctx);
                for f in f.iter_mut() {
                    f.location.line = Some(unit.line);
                    f.location.display = format!("{}:{}", display, unit.line);
                }
                findings.append(&mut f);
                let _ = idx;
            }
        }
        Syntax::Crontab => {
            for (lineno, line) in text.lines().enumerate() {
                let lineno = lineno as u32 + 1;
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                // `NAME=value` environment lines in a crontab.
                if let Some(eq) = crate::scan::sh::assignment_split(trimmed) {
                    let name = &trimmed[..eq];
                    let value = &trimmed[eq + 1..];
                    let loc = LocationRef::file(Surface::CronEntry, &display, lineno, mode);
                    let ctx = Context {
                        location: loc,
                        process: None,
                        salt,
                    };
                    let mut f = detect::scan_env(name, value, &ctx);
                    for f in f.iter_mut() {
                        f.location.line = Some(lineno);
                        f.location.display = format!("{}:{}", display, lineno);
                    }
                    findings.append(&mut f);
                    continue;
                }
                let cmd = strip_cron_schedule(trimmed);
                if cmd.is_empty() {
                    continue;
                }
                let loc = LocationRef::file(Surface::CronEntry, &display, lineno, mode);
                let ctx = Context {
                    location: loc,
                    process: None,
                    salt,
                };
                let mut f = detect::scan_line(cmd, Surface::CronEntry, &ctx);
                for f in f.iter_mut() {
                    f.location.line = Some(lineno);
                    f.location.display = format!("{}:{}", display, lineno);
                    f.notes.push("scheduled command: fix the script or unit, not the history".into());
                }
                findings.append(&mut f);
            }
        }
        Syntax::SystemdUnit => {
            for (lineno, line) in text.lines().enumerate() {
                let lineno = lineno as u32 + 1;
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                    continue;
                }
                let Some((key, value)) = trimmed.split_once('=') else {
                    continue;
                };
                let key = key.trim();
                let value = value.trim();
                let loc = LocationRef::file(Surface::SystemdUnit, &display, lineno, mode);
                let ctx = Context {
                    location: loc,
                    process: None,
                    salt,
                };
                let mut f = if key.eq_ignore_ascii_case("Environment") {
                    // `Environment=A=1 B=2`
                    let mut acc = Vec::new();
                    for part in split_systemd_words(value) {
                        if let Some(eq) = crate::scan::sh::assignment_split(&part) {
                            acc.extend(detect::scan_env(&part[..eq], &part[eq + 1..], &ctx));
                        }
                    }
                    acc
                } else if key.eq_ignore_ascii_case("ExecStart")
                    || key.eq_ignore_ascii_case("ExecStartPre")
                    || key.eq_ignore_ascii_case("ExecStartPost")
                    || key.eq_ignore_ascii_case("ExecReload")
                {
                    detect::scan_line(value, Surface::SystemdUnit, &ctx)
                } else {
                    Vec::new()
                };
                for f in f.iter_mut() {
                    f.location.line = Some(lineno);
                    f.location.display = format!("{}:{}", display, lineno);
                }
                findings.append(&mut f);
            }
        }
        Syntax::History => {
            for (lineno, line) in text.lines().enumerate() {
                let lineno = lineno as u32 + 1;
                // zsh extended history: `: 1700000000:0;command`
                let cmd = match line.strip_prefix(": ") {
                    Some(rest) => rest.split_once(';').map(|(_, c)| c).unwrap_or(rest),
                    None => line,
                };
                if cmd.trim().is_empty() {
                    continue;
                }
                let loc = LocationRef::file(Surface::HistoryFile, &display, lineno, mode);
                let ctx = Context {
                    location: loc,
                    process: None,
                    salt,
                };
                let mut f = detect::scan_line(cmd, Surface::HistoryFile, &ctx);
                for f in f.iter_mut() {
                    f.location.line = Some(lineno);
                    f.location.display = format!("{}:{}", display, lineno);
                    f.notes.push(
                        "history is the weakest evidence: the command may have failed, and a `$VAR` here was never the value"
                            .into(),
                    );
                }
                findings.append(&mut f);
            }
        }
        Syntax::Config => {
            for (lineno, line) in text.lines().enumerate() {
                let lineno = lineno as u32 + 1;
                let trimmed = line.trim();
                if trimmed.is_empty()
                    || trimmed.starts_with('#')
                    || trimmed.starts_with(';')
                    || trimmed.starts_with('[')
                {
                    continue;
                }
                if let Some((key, value)) = trimmed.split_once('=').or_else(|| trimmed.split_once(':'))
                {
                    let key = key.trim();
                    let value = value.trim();
                    let loc = LocationRef::file(Surface::ConfigFile, &display, lineno, mode);
                    let ctx = Context {
                        location: loc,
                        process: None,
                        salt,
                    };
                    let mut f = detect::scan_env(key, value, &ctx);
                    for f in f.iter_mut() {
                        f.location.line = Some(lineno);
                        f.location.display = format!("{}:{}", display, lineno);
                    }
                    findings.append(&mut f);
                }
            }
        }
    }
    findings
}

#[derive(Debug, Clone)]
pub struct LogicalLine {
    /// Text with backslash continuations joined by a single space.
    pub text: String,
    /// 1-based line number of the first physical line.
    pub line: u32,
}

/// Join backslash-continued shell lines so a `mysql` invocation split over
/// several lines is analysed as one command.
pub fn logical_lines(text: &str) -> Vec<LogicalLine> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut start_line = 1u32;
    let mut pending = false;
    for (i, raw) in text.lines().enumerate() {
        let lineno = i as u32 + 1;
        let trimmed_end = raw.trim_end();
        let continues = trimmed_end.ends_with('\\')
            && !trimmed_end.ends_with("\\\\")
            // Inside single quotes a trailing backslash is literal; this is a
            // heuristic, and the detector tolerates a wrongly joined line.
            && !odd_quotes(&cur);
        if cur.is_empty() {
            start_line = lineno;
        }
        if continues {
            cur.push_str(trimmed_end.trim_end_matches('\\'));
            cur.push(' ');
            pending = true;
        } else {
            cur.push_str(raw);
            out.push(LogicalLine {
                text: std::mem::take(&mut cur),
                line: start_line,
            });
            pending = false;
        }
    }
    if pending || !cur.is_empty() {
        out.push(LogicalLine {
            text: cur,
            line: start_line,
        });
    }
    out
}

fn odd_quotes(s: &str) -> bool {
    let mut single = false;
    let mut i = s.chars().peekable();
    while let Some(c) = i.next() {
        match c {
            '\\' => {
                i.next();
            }
            '\'' => single = !single,
            _ => {}
        }
    }
    single
}

/// Drop the five schedule fields (and an optional user field) from a crontab
/// line, returning the command.
pub fn strip_cron_schedule(line: &str) -> &str {
    // `@reboot cmd`, `@daily cmd`: one shorthand field instead of five.
    if line.starts_with('@') {
        return match line.find(char::is_whitespace) {
            Some(i) => line[i..].trim_start(),
            None => "",
        };
    }
    let mut rest = line.trim_start();
    for _ in 0..5 {
        let t = rest.trim_start();
        let Some(end) = t.find(char::is_whitespace) else {
            return "";
        };
        rest = &t[end..];
    }
    rest.trim_start()
}

fn split_systemd_words(v: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote = None;
    for c in v.chars() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else {
                    cur.push(c);
                }
            }
            None => {
                if c == '"' || c == '\'' {
                    quote = Some(c);
                } else if c.is_whitespace() {
                    if !cur.is_empty() {
                        out.push(std::mem::take(&mut cur));
                    }
                } else {
                    cur.push(c);
                }
            }
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Recursively collect candidate files under `roots`, with simple filtering of
/// virtual filesystems and noise directories.
pub fn walk(roots: &[PathBuf], max_files: usize) -> Vec<PathBuf> {
    const SKIP_DIRS: &[&str] = &[
        "proc", "sys", "dev", "run", "node_modules", ".git", "__pycache__",
        ".cache", "site-packages", "vendor",
    ];
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = roots.to_vec();
    while let Some(dir) = stack.pop() {
        if out.len() >= max_files {
            break;
        }
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for entry in rd.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                if SKIP_DIRS.contains(&name.as_str()) {
                    continue;
                }
                stack.push(path);
            } else if ft.is_file() && looks_interesting(&path) {
                out.push(path);
                if out.len() >= max_files {
                    break;
                }
            }
        }
    }
    out.sort();
    out
}

fn looks_interesting(p: &Path) -> bool {
    let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let lower = name.to_ascii_lowercase();
    if name.ends_with("_history") || name == ".bash_history" || name == ".zsh_history" {
        return true;
    }
    // Crontab drop-ins are frequently stored without an extension, and a
    // saved copy is often named `crontab` or `crontab.txt`.
    if lower.starts_with("crontab") || lower.ends_with(".cron") || lower == "crontab" {
        return true;
    }
    matches!(
        p.extension().and_then(|e| e.to_str()),
        Some("sh") | Some("bash") | Some("service") | Some("timer") | Some("cnf") | Some("conf")
    ) || name.ends_with(".sh")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;
    use std::path::PathBuf;

    fn scan(src: &str, syntax: Syntax) -> Vec<Finding> {
        scan_text(
            src,
            &PathBuf::from("/tmp/t.sh"),
            syntax,
            Some(0o644),
            None,
        )
    }

    #[test]
    fn shell_continuation_joins_one_command() {
        let src = "mysql \\\n  -u app \\\n  -pHunter2Secret \\\n  mydb\n";
        let fs = scan(src, Syntax::Shell);
        assert_eq!(fs.len(), 1, "{fs:#?}");
        assert_eq!(fs[0].location.line, Some(1));
    }

    #[test]
    fn shell_comment_lines_ignored() {
        let src = "# mysql -pHunter2Secret\nmysql -u app mydb\n";
        let fs = scan(src, Syntax::Shell);
        assert!(fs.is_empty(), "{fs:#?}");
    }

    #[test]
    fn crontab_env_and_command() {
        let src = "DB_PASSWORD=Sup3rS3cret\n*/5 * * * * app /opt/backup.sh --token=OtherSecret9\n";
        let fs = scan(src, Syntax::Crontab);
        assert_eq!(fs.len(), 2, "{fs:#?}");
        assert!(fs.iter().any(|f| f.location.display.contains(":1")));
        assert!(fs.iter().any(|f| f.location.display.contains(":2")));
        assert!(fs.iter().all(|f| f.location.surface == Surface::CronEntry));
    }

    #[test]
    fn crontab_schedule_is_stripped() {
        assert_eq!(strip_cron_schedule("*/5 * * * * app /opt/x.sh"), "app /opt/x.sh");
        assert_eq!(strip_cron_schedule("@reboot /opt/x.sh"), "/opt/x.sh");
    }

    #[test]
    fn systemd_environment_and_execstart() {
        let src = "[Service]\nEnvironment=\"DB_PASSWORD=Sup3rS3cret\"\nExecStart=/usr/bin/mysql -pHunter2Secret\n";
        let fs = scan(src, Syntax::SystemdUnit);
        assert_eq!(fs.len(), 2, "{fs:#?}");
        assert!(fs.iter().all(|f| f.location.surface == Surface::SystemdUnit));
        assert_eq!(fs[0].location.line, Some(2));
        assert_eq!(fs[1].location.line, Some(3));
    }

    #[test]
    fn history_multi_line_and_zsh_format() {
        let src = ": 1700000000:0;mysql -pHunter2Secret db\nredis-cli -a OtherSecret9 ping\n";
        let fs = scan(src, Syntax::History);
        assert_eq!(fs.len(), 2);
        assert!(fs.iter().all(|f| f.location.surface == Surface::HistoryFile));
        assert!(fs[0].notes.iter().any(|n| n.contains("weakest")));
    }

    #[test]
    fn config_ini_and_pgpass() {
        let src = "[client]\npassword = Sup3rS3cret\nhost = db\n";
        let fs = scan(src, Syntax::Config);
        assert_eq!(fs.len(), 1, "{fs:#?}");
        assert_eq!(fs[0].location.surface, Surface::ConfigFile);
    }

    #[test]
    fn syntax_detected_from_filename() {
        assert_eq!(Syntax::from_path(Path::new("/x/a.sh")), Syntax::Shell);
        assert_eq!(
            Syntax::from_path(Path::new("/etc/systemd/system/a.service")),
            Syntax::SystemdUnit
        );
        assert_eq!(Syntax::from_path(Path::new("/home/u/.bash_history")), Syntax::History);
        assert_eq!(Syntax::from_path(Path::new("/home/u/.pgpass")), Syntax::Config);
    }

    #[test]
    fn world_readable_script_is_more_severe_than_private_one() {
        let pubf = scan_text(
            "mysql -pSup3rS3cret db",
            &PathBuf::from("/tmp/pub.sh"),
            Syntax::Shell,
            Some(0o644),
            None,
        );
        let privf = scan_text(
            "mysql -pSup3rS3cret db",
            &PathBuf::from("/root/priv.sh"),
            Syntax::Shell,
            Some(0o600),
            None,
        );
        assert_eq!(pubf[0].severity, Severity::High);
        assert!(privf[0].severity < pubf[0].severity);
    }
}
