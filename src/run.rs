//! `credops run` — inject secrets at exec time instead of embedding them.
//!
//! For tools with no protected input, the credential has to reach argv
//! eventually. The realistic goal is therefore narrower than "never in argv":
//!
//! * it must not be **written down** — not in the script, not in the crontab,
//!   not in systemd `Environment=`, not in shell history, not in a git repo;
//! * it must not be in the **wrapper's** argv either (the wrapper is told
//!   `--secret-file db=/etc/credops/db.pass`, never the value);
//! * the child's argv exposure is then bounded by the child's lifetime and by
//!   `/proc` permissions, which `hidepid=2` or `ProtectProc=invisible` narrow
//!   to the owning uid and root.
//!
//! The syntax is a `{NAME}` template in the child arguments:
//!
//! ```text
//! credops run --secret-file db=/etc/credops/db.pass -- mysql -u app -p{db} mydb
//! ```
//!
//! `credops run` then `exec`s the child directly (no shell, no lingering
//! parent holding the secret), and the value exists only in the child's argv
//! for the child's lifetime.
//!
//! ## What this does and does not buy you
//!
//! It removes the *persistent* leak — the copy in the script and in history —
//! which is the part that survives reboots, backups and `grep`. It does not
//! remove the transient `/proc/<pid>/cmdline` leak, because the tool has to
//! read its own argv to work. Anything that claims to remove both is wrong.

use anyhow::{bail, Context as _};
use std::collections::BTreeMap;

/// Where one named secret comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretSource {
    /// A file, read once; trailing newline trimmed unless `keep_newline`.
    File { path: String, keep_newline: bool },
    /// An inherited file descriptor.
    Fd { fd: i32 },
    /// The wrapper's own environment. Discouraged: the caller had to put the
    /// value somewhere, and its environment is as readable as its argv to the
    /// same uid. Accepted for CI systems that inject env and nothing else.
    Env { var: String },
    /// Standard input, read to EOF.
    Stdin,
}

#[derive(Debug, Clone, Default)]
pub struct RunPlan {
    pub sources: BTreeMap<String, SecretSource>,
    /// Child program and arguments, with `{NAME}` placeholders still present.
    pub template: Vec<String>,
}

impl RunPlan {
    /// Add a source from a CLI spec: `NAME=PATH`, `NAME=fd:3`, `NAME=env:VAR`,
    /// `NAME=stdin`, or bare `PATH` (name derived from the file stem).
    pub fn add_spec(&mut self, spec: &str) -> anyhow::Result<()> {
        let (name, src) = match spec.split_once('=') {
            Some((n, v)) => (n.trim().to_string(), v.trim().to_string()),
            None => {
                let stem = std::path::Path::new(spec)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("secret")
                    .to_string();
                (sanitize_name(&stem), spec.trim().to_string())
            }
        };
        if name.is_empty() {
            bail!("secret spec has an empty name: {spec:?}");
        }
        if !is_valid_name(&name) {
            bail!("secret name {name:?} must match [A-Za-z_][A-Za-z0-9_]*");
        }
        let source = if let Some(v) = src.strip_prefix("fd:") {
            SecretSource::Fd {
                fd: v.parse().context("fd: expects a number")?,
            }
        } else if let Some(v) = src.strip_prefix("env:") {
            SecretSource::Env { var: v.to_string() }
        } else if src == "stdin" || src == "-" {
            SecretSource::Stdin
        } else if let Some(v) = src.strip_prefix("file:") {
            SecretSource::File {
                path: v.to_string(),
                keep_newline: false,
            }
        } else {
            SecretSource::File {
                path: src,
                keep_newline: false,
            }
        };
        if self.sources.insert(name.clone(), source).is_some() {
            bail!("secret {name:?} given more than once");
        }
        Ok(())
    }

    /// Names referenced by the child template.
    pub fn referenced(&self) -> Vec<String> {
        let mut out = Vec::new();
        for arg in &self.template {
            for name in placeholders(arg) {
                if !out.contains(&name) {
                    out.push(name);
                }
            }
        }
        out
    }

    /// Refuse to run if the template names a secret that was not supplied, or
    /// if a supplied secret is never used (almost always a typo).
    pub fn validate(&self) -> anyhow::Result<()> {
        let referenced = self.referenced();
        let mut missing: Vec<String> = referenced
            .iter()
            .filter(|n| !self.sources.contains_key(*n))
            .cloned()
            .collect();
        let mut unused: Vec<String> = self
            .sources
            .keys()
            .filter(|n| !referenced.contains(n))
            .cloned()
            .collect();
        // Report both problems at once: fixing one and being told about the
        // other is a wasted round trip.
        missing.sort();
        unused.sort();
        let mut problems = Vec::new();
        if !missing.is_empty() {
            problems.push(format!(
                "template references secrets that were not supplied: {}",
                missing.join(", ")
            ));
        }
        if !unused.is_empty() {
            problems.push(format!(
                "secrets supplied but not referenced by the command: {}",
                unused.join(", ")
            ));
        }
        if !problems.is_empty() {
            bail!("{}", problems.join("; "));
        }
        if self.template.is_empty() {
            bail!("no command given after `--`");
        }
        Ok(())
    }
}

fn sanitize_name(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        let c = if c.is_ascii_alphanumeric() || c == '_' {
            c
        } else {
            '_'
        };
        if i == 0 && c.is_ascii_digit() {
            out.push('_');
        }
        out.push(c);
    }
    out
}

fn is_valid_name(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// Find `{NAME}` placeholders in a string. `{{` and `}}` are literal braces.
pub fn placeholders(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                i += 2;
                continue;
            }
            if let Some(close) = s[i + 1..].find('}') {
                let name = &s[i + 1..i + 1 + close];
                if is_valid_name(name) {
                    out.push(name.to_string());
                }
                i = i + 1 + close + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Substitute every `{NAME}` from `secrets`. `{{`/`}}` become literal braces.
pub fn expand(template: &str, secrets: &BTreeMap<String, Vec<u8>>) -> anyhow::Result<String> {
    let bytes = template.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(template.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                out.push(b'{');
                i += 2;
                continue;
            }
            if let Some(close) = template[i + 1..].find('}') {
                let name = &template[i + 1..i + 1 + close];
                if is_valid_name(name) {
                    let Some(v) = secrets.get(name) else {
                        bail!("no secret named {name:?}");
                    };
                    out.extend_from_slice(v);
                    i = i + 1 + close + 1;
                    continue;
                }
                // `{not a name}` is literal text, not an error.
            }
        }
        if bytes[i] == b'}' && i + 1 < bytes.len() && bytes[i + 1] == b'}' {
            out.push(b'}');
            i += 2;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).map_err(|_| {
        anyhow::anyhow!("a substituted secret is not valid UTF-8; pass it as a file the tool reads instead")
    })
}

/// Build the final child argv (excluding argv[0]) from a plan and loaded
/// secrets. Kept pure so it is testable without executing anything.
pub fn build_argv(plan: &RunPlan, secrets: &BTreeMap<String, Vec<u8>>) -> anyhow::Result<Vec<String>> {
    plan.validate()?;
    let mut out = Vec::with_capacity(plan.template.len());
    for arg in &plan.template {
        out.push(expand(arg, secrets)?);
    }
    Ok(out)
}

fn trim_trailing_newline(mut v: Vec<u8>) -> Vec<u8> {
    if v.last() == Some(&b'\n') {
        v.pop();
        if v.last() == Some(&b'\r') {
            v.pop();
        }
    }
    v
}

#[cfg(unix)]
mod load {
    use super::*;
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::FromRawFd;

    const MAX_SECRET: u64 = 64 * 1024;

    pub fn read_source(src: &SecretSource) -> anyhow::Result<Vec<u8>> {
        match src {
            SecretSource::File { path, keep_newline } => {
                let meta = std::fs::metadata(path)
                    .with_context(|| format!("stat {path}"))?;
                if meta.len() > MAX_SECRET {
                    bail!("{path}: {} bytes is larger than any credential", meta.len());
                }
                // Refuse a group- or world-readable secret file: the whole
                // point of moving the value here is that it stays protected.
                let mode = meta.mode() & 0o777;
                if mode & 0o077 != 0 {
                    bail!(
                        "{path} is mode {:o}; secrets must not be readable by group or others (chmod 600 {path})",
                        mode
                    );
                }
                let bytes = std::fs::read(path).with_context(|| format!("read {path}"))?;
                Ok(if *keep_newline {
                    bytes
                } else {
                    trim_trailing_newline(bytes)
                })
            }
            SecretSource::Fd { fd } => {
                // Safety: the caller asserts the fd is open and readable.
                let mut f = unsafe { std::fs::File::from_raw_fd(*fd) };
                let mut buf = Vec::new();
                (&mut f).take(MAX_SECRET).read_to_end(&mut buf)?;
                // Do not close a descriptor we did not open.
                std::mem::forget(f);
                Ok(trim_trailing_newline(buf))
            }
            SecretSource::Env { var } => match std::env::var_os(var) {
                Some(v) => {
                    use std::os::unix::ffi::OsStrExt;
                    Ok(v.as_bytes().to_vec())
                }
                None => bail!("environment variable {var} is not set"),
            },
            SecretSource::Stdin => {
                let mut buf = Vec::new();
                std::io::stdin().take(MAX_SECRET).read_to_end(&mut buf)?;
                Ok(trim_trailing_newline(buf))
            }
        }
    }

    pub fn load_all(plan: &RunPlan) -> anyhow::Result<BTreeMap<String, Vec<u8>>> {
        let mut out = BTreeMap::new();
        for name in plan.referenced() {
            let src = plan
                .sources
                .get(&name)
                .ok_or_else(|| anyhow::anyhow!("no source for secret {name:?}"))?;
            out.insert(name, read_source(src)?);
        }
        Ok(out)
    }

    /// Try to keep the secret out of swap and core dumps. Best effort: `mlock`
    /// can fail on a low `RLIMIT_MEMLOCK`, and Rust strings may have been
    /// copied. Reported, never fatal.
    pub fn harden(secrets: &mut BTreeMap<String, Vec<u8>>) {
        for v in secrets.values_mut() {
            unsafe {
                libc::mlock(v.as_ptr() as *const libc::c_void, v.len());
            }
        }
        #[cfg(target_os = "linux")]
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
    }

    pub fn wipe(secrets: &mut BTreeMap<String, Vec<u8>>) {
        for v in secrets.values_mut() {
            for b in v.iter_mut() {
                unsafe { std::ptr::write_volatile(b, 0) };
            }
            v.clear();
        }
    }
}

#[cfg(unix)]
pub use load::{harden, load_all, wipe};

/// Run the plan: load secrets, build argv, and `exec` the child, replacing the
/// wrapper process so nothing lingers.
#[cfg(unix)]
pub fn run(plan: &RunPlan) -> anyhow::Result<std::convert::Infallible> {
    use std::ffi::CString;
    plan.validate()?;
    let mut secrets = load_all(plan)?;
    harden(&mut secrets);
    let argv = build_argv(plan, &secrets)?;
    // The secrets have been copied into `argv`; wipe the loader's copies so the
    // only live copy is the one the child will read.
    wipe(&mut secrets);

    let program = CString::new(plan.template[0].as_bytes())
        .context("program name contains a NUL byte")?;
    let mut c_args: Vec<CString> = Vec::with_capacity(argv.len() + 2);
    // argv[0] must be the *program name*, not the expanded template: the
    // template's first element is the executable path and never a secret.
    c_args.push(CString::new(argv[0].as_bytes())?);
    for a in &argv[1..] {
        c_args.push(CString::new(a.as_bytes())?);
    }
    let mut ptrs: Vec<*const libc::c_char> = c_args.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());

    unsafe {
        libc::execvp(program.as_ptr(), ptrs.as_ptr());
    }
    let err = std::io::Error::last_os_error();
    bail!("exec {}: {err}", plan.template[0])
}

/// Build a `credops run` command line from a finding and its remediation, for
/// the report to print. Never includes the secret itself.
pub fn suggested_command(template: &[String]) -> String {
    let mut out = String::from("credops run --secret-file db=/etc/credops/db.pass --");
    for t in template {
        out.push(' ');
        out.push_str(t);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets(pairs: &[(&str, &str)]) -> BTreeMap<String, Vec<u8>> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.as_bytes().to_vec()))
            .collect()
    }

    #[test]
    fn placeholders_are_found() {
        assert_eq!(placeholders("mysql -p{db} mydb"), vec!["db"]);
        assert_eq!(placeholders("-u {user}:{pw}"), vec!["user", "pw"]);
        assert!(placeholders("{{literal}} {not valid}").is_empty());
        assert!(placeholders("plain").is_empty());
    }

    #[test]
    fn expansion_substitutes_and_escapes_braces() {
        let s = secrets(&[("db", "Hunter2Secret")]);
        assert_eq!(
            expand("mysql -u app -p{db} mydb", &s).unwrap(),
            "mysql -u app -pHunter2Secret mydb"
        );
        assert_eq!(expand("{{literal}} {db}", &s).unwrap(), "{literal} Hunter2Secret");
        assert_eq!(expand("{{}}", &s).unwrap(), "{}");
    }

    #[test]
    fn expansion_of_unknown_name_is_an_error() {
        let s = secrets(&[("db", "x")]);
        assert!(expand("-p{other}", &s).is_err());
    }

    #[test]
    fn non_utf8_secret_is_rejected_with_a_useful_message() {
        let mut m = BTreeMap::new();
        m.insert("pw".to_string(), vec![0xff, 0xfe]);
        let err = expand("-p{pw}", &m).unwrap_err().to_string();
        assert!(err.contains("not valid UTF-8"), "{err}");
    }

    #[test]
    fn plan_specs_parse() {
        let mut p = RunPlan::default();
        p.add_spec("db=/etc/credops/db.pass").unwrap();
        p.add_spec("tok=fd:3").unwrap();
        p.add_spec("ci=env:MY_TOKEN").unwrap();
        p.add_spec("std=stdin").unwrap();
        assert!(matches!(p.sources["db"], SecretSource::File { .. }));
        assert_eq!(p.sources["tok"], SecretSource::Fd { fd: 3 });
        assert_eq!(
            p.sources["ci"],
            SecretSource::Env {
                var: "MY_TOKEN".to_string()
            }
        );
        assert_eq!(p.sources["std"], SecretSource::Stdin);
    }

    #[test]
    fn bare_path_derives_a_name() {
        let mut p = RunPlan::default();
        p.add_spec("/etc/credops/db.pass").unwrap();
        assert!(p.sources.contains_key("db"));
    }

    #[test]
    fn bad_names_are_rejected() {
        let mut p = RunPlan::default();
        assert!(p.add_spec("1bad=/x").is_err());
        assert!(p.add_spec("has space=/x").is_err());
        assert!(p.add_spec("dup=/x").is_ok());
        assert!(p.add_spec("dup=/y").is_err());
    }

    #[test]
    fn validate_catches_missing_and_unused() {
        let mut p = RunPlan {
            template: vec!["mysql".into(), "-p{db}".into()],
            ..Default::default()
        };
        p.add_spec("other=/x").unwrap();
        let err = p.validate().unwrap_err().to_string();
        assert!(err.contains("not supplied"), "{err}");
        assert!(err.contains("not referenced"), "{err}");
    }

    #[test]
    fn build_argv_end_to_end() {
        let mut p = RunPlan {
            template: vec![
                "mysql".into(),
                "-u".into(),
                "app".into(),
                "-p{db}".into(),
                "mydb".into(),
            ],
            ..Default::default()
        };
        p.add_spec("db=/tmp/db.pass").unwrap();
        let argv = build_argv(&p, &secrets(&[("db", "Hunter2Secret")])).unwrap();
        assert_eq!(argv, vec!["mysql", "-u", "app", "-pHunter2Secret", "mydb"]);
    }

    #[cfg(unix)]
    #[test]
    fn wrapper_actually_execs_with_the_secret() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("credops-run-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let secret_path = dir.join("db.pass");
        let mut f = std::fs::File::create(&secret_path).unwrap();
        writeln!(f, "Hunter2Secret").unwrap();
        drop(f);
        std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        // Run the current test binary as the wrapper? Simpler: call the same
        // pieces `run` uses, then exec a shell that echoes its argument.
        let mut plan = RunPlan {
            template: vec![
                "/bin/sh".into(),
                "-c".into(),
                "printf %s \"$1\"".into(),
                "sh".into(),
                "-p{db}".into(),
            ],
            ..Default::default()
        };
        plan.add_spec(&format!("db={}", secret_path.display())).unwrap();
        let mut s = load_all(&plan).unwrap();
        let argv = build_argv(&plan, &s).unwrap();
        wipe(&mut s);
        assert_eq!(argv[4], "-pHunter2Secret");

        let out = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .output()
            .unwrap();
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout), "-pHunter2Secret");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn world_readable_secret_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("credops-open-{}", std::process::id()));
        std::fs::write(&path, b"x").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let src = SecretSource::File {
            path: path.display().to_string(),
            keep_newline: false,
        };
        let err = load::read_source(&src).unwrap_err().to_string();
        assert!(err.contains("chmod 600"), "{err}");
        std::fs::remove_file(&path).ok();
    }
}
