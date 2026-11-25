//! CLI.

use anyhow::Context as _;
use clap::{Parser, Subcommand, ValueEnum};
use credops::collect::{self, files, proc};
use credops::model::{Finding, Severity};
use credops::remediate;
use credops::report;
use credops::run::{self, RunPlan};
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "credops",
    version,
    about = "Find credentials on command lines, in environments and in shell history, and migrate them to protected channels",
    long_about = None,
)]
struct Cli {
    /// Salt for value fingerprints. Without it, fingerprints are unsalted and
    /// must not be shared: they would let anyone test a guessed password.
    #[arg(long, global = true)]
    salt: Option<String>,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Scan this host: files, cron, systemd, live processes and audit logs.
    Scan(ScanArgs),
    /// Scan one file or one line of text (used by tests and CI hooks).
    Check(CheckArgs),
    /// Turn findings into an ordered migration plan.
    Plan(PlanArgs),
    /// Inject secrets at exec time instead of writing them into scripts.
    Run(RunArgs),
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum Format {
    Text,
    Json,
    Sarif,
}

#[derive(clap::Args, Debug)]
struct ScanArgs {
    /// Roots to walk for scripts, units, crontabs and history files.
    #[arg(long = "root", value_name = "DIR")]
    roots: Vec<PathBuf>,
    /// Also scan the well-known crontab and systemd unit directories.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    well_known_paths: bool,
    /// Scan live processes via /proc (fallback for long-lived processes).
    #[arg(long)]
    proc: bool,
    /// Read an audit log (or `-` for stdin) instead of a live one.
    #[arg(long, value_name = "FILE")]
    audit_log: Option<String>,
    /// Read an eBPF agent's JSON-lines event feed.
    #[arg(long, value_name = "FILE")]
    ebpf_feed: Option<String>,
    /// Scan user home histories under /home.
    #[arg(long)]
    histories: bool,
    /// Minimum severity to report.
    #[arg(long, default_value = "low")]
    min_severity: String,
    #[arg(long, value_enum, default_value = "text")]
    format: Format,
    /// Emit the migration plan instead of the raw findings.
    #[arg(long)]
    plan: bool,
    /// Exit non-zero when a finding at or above this severity exists.
    #[arg(long, value_name = "SEV")]
    fail_on: Option<String>,
    /// Hard cap on files walked, so a scan cannot run away.
    #[arg(long, default_value_t = 200_000)]
    max_files: usize,
    #[arg(long, default_value_t = 4 * 1024 * 1024)]
    max_file_bytes: u64,
}

#[derive(clap::Args, Debug)]
struct CheckArgs {
    /// File to check. Use `-` to read stdin.
    #[arg(value_name = "FILE")]
    path: String,
    /// Treat the input as this syntax instead of guessing from the name.
    #[arg(long, value_enum)]
    syntax: Option<SyntaxArg>,
    /// Treat the input as one command line rather than a file.
    #[arg(long)]
    line: bool,
    /// Scan as if it were an argv (variable references are treated as expanded).
    #[arg(long)]
    argv: bool,
    #[arg(long, value_enum, default_value = "text")]
    format: Format,
    #[arg(long, value_name = "SEV")]
    fail_on: Option<String>,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum SyntaxArg {
    Shell,
    Crontab,
    Systemd,
    History,
    Config,
}

impl From<SyntaxArg> for files::Syntax {
    fn from(s: SyntaxArg) -> Self {
        match s {
            SyntaxArg::Shell => files::Syntax::Shell,
            SyntaxArg::Crontab => files::Syntax::Crontab,
            SyntaxArg::Systemd => files::Syntax::SystemdUnit,
            SyntaxArg::History => files::Syntax::History,
            SyntaxArg::Config => files::Syntax::Config,
        }
    }
}

#[derive(clap::Args, Debug)]
struct PlanArgs {
    /// Same inputs as `scan`; a plan is built from the same findings.
    #[command(flatten)]
    scan: ScanArgs,
    /// Write the plan as Markdown instead of text.
    #[arg(long)]
    markdown: bool,
}

#[derive(clap::Args, Debug)]
struct RunArgs {
    /// Secret sources: `NAME=PATH`, `NAME=fd:N`, `NAME=env:VAR`, `NAME=stdin`.
    /// A bare `PATH` derives the name from the file stem.
    #[arg(long = "secret-file", value_name = "SPEC")]
    secret_file: Vec<String>,
    /// Command to run; `{NAME}` in any argument is replaced.
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
    /// Print the argv that would be executed, with secrets masked.
    #[arg(long)]
    dry_run: bool,
}

fn main() {
    let cli = Cli::parse();
    let salt = cli.salt.clone().or_else(|| std::env::var("CREDOPS_SALT").ok());
    let code = match run_cli(cli, salt.as_deref()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("credops: {e:#}");
            2
        }
    };
    std::process::exit(code);
}

fn run_cli(cli: Cli, salt: Option<&str>) -> anyhow::Result<i32> {
    match cli.cmd {
        Command::Scan(args) => do_scan(args, salt, false),
        Command::Plan(args) => do_scan(args.scan, salt, true),
        Command::Check(args) => do_check(args, salt),
        Command::Run(args) => do_run(args),
    }
}

fn do_scan(args: ScanArgs, salt: Option<&str>, want_plan: bool) -> anyhow::Result<i32> {
    let min = parse_sev(&args.min_severity)?;
    let fail_on = args.fail_on.as_deref().map(parse_sev).transpose()?;
    let mut findings: Vec<Finding> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    let mut roots = args.roots.clone();
    if args.well_known_paths || args.histories {
        for p in well_known_roots(args.histories) {
            if p.exists() && !roots.contains(&p) {
                roots.push(p);
            }
        }
    }
    if !roots.is_empty() {
        let opts = files::FileScanOptions {
            max_bytes: args.max_file_bytes,
            salt: salt.map(|s| s.to_string()),
        };
        let candidates = files::walk(&roots, args.max_files);
        let mut scanned = 0usize;
        let mut skipped = 0usize;
        for path in &candidates {
            let syntax = files::Syntax::from_path(path);
            match files::scan_file(path, syntax, &opts) {
                Ok(res) => {
                    scanned += res.files_scanned;
                    skipped += res.skipped.len();
                    findings.extend(res.findings);
                }
                Err(e) => notes.push(format!("{}: {e}", path.display())),
            }
            if scanned >= args.max_files {
                notes.push(format!("stopped after {scanned} files (--max-files)"));
                break;
            }
        }
        notes.push(format!(
            "walked {} candidate file(s), scanned {scanned}, skipped {skipped}",
            candidates.len()
        ));
    }

    if let Some(log) = &args.audit_log {
        let text = read_input(log)?;
        findings.extend(collect::audit::scan_log(&text, salt));
    }

    if let Some(feed) = &args.ebpf_feed {
        let text = read_input(feed)?;
        let (events, bad) = collect::bpf::parse_events(&text);
        if bad > 0 {
            notes.push(format!("{bad} malformed event line(s) skipped"));
        }
        findings.extend(collect::bpf::scan_events(&events, salt));
    }

    if args.proc {
        if cfg!(not(target_os = "linux")) {
            notes.push("/proc scanning is only available on Linux".into());
        }
        let opts = proc::ProcOptions {
            salt: salt.map(|s| s.to_string()),
            ..Default::default()
        };
        findings.extend(proc::collect(&opts));
    }

    findings = collect::dedup(findings);
    let mut stdout = std::io::stdout();

    if want_plan {
        let plan = remediate::build(&findings);
        report::render_plan(&mut stdout, &plan)?;
    } else {
        match args.format {
            Format::Text => {
                report::render_text(&mut stdout, &findings, min)?;
                writeln!(stdout, "{}", report::headline(&findings))?;
                let mut rot = Vec::new();
                report::render_rotation(&mut rot, &findings)?;
                if !rot.is_empty() {
                    writeln!(stdout)?;
                    stdout.write_all(&rot)?;
                }
            }
            Format::Json => report::render_json(&mut stdout, &findings, salt.is_some())?,
            Format::Sarif => report::render_sarif(&mut stdout, &findings)?,
        }
    }
    for n in &notes {
        eprintln!("note: {n}");
    }
    if salt.is_none() && args.format == Format::Json {
        eprintln!("warning: no --salt/CREDOPS_SALT set; fingerprints are unsalted and must not be shared");
    }

    let code = match fail_on {
        Some(sev) if findings.iter().any(|f| f.is_actionable() && f.severity >= sev) => 1,
        _ => 0,
    };
    Ok(code)
}

fn do_check(args: CheckArgs, salt: Option<&str>) -> anyhow::Result<i32> {
    let text = read_input(&args.path)?;
    let fail_on = args.fail_on.as_deref().map(parse_sev).transpose()?;
    let findings: Vec<Finding> = if args.line || args.argv {
        let surface = if args.argv {
            credops::model::Surface::ProcCmdline
        } else {
            credops::model::Surface::ScriptFile
        };
        let loc = credops::model::LocationRef {
            surface,
            display: if args.path == "-" { "<stdin>".to_string() } else { args.path.clone() },
            file: if args.path == "-" { None } else { Some(args.path.clone()) },
            line: Some(1),
            mode: None,
            owner_uid: None,
        };
        let ctx = credops::scan::detect::Context {
            location: loc,
            process: None,
            salt,
        };
        credops::scan::detect::scan_line(text.trim_end_matches('\n'), surface, &ctx)
    } else {
        let path = if args.path == "-" {
            PathBuf::from("<stdin>")
        } else {
            PathBuf::from(&args.path)
        };
        let syntax = args
            .syntax
            .map(files::Syntax::from)
            .unwrap_or_else(|| files::Syntax::from_path(&path));
        files::scan_text(&text, &path, syntax, None, salt)
    };
    let mut stdout = std::io::stdout();
    match args.format {
        Format::Text => report::render_text(&mut stdout, &findings, Severity::Info)?,
        Format::Json => report::render_json(&mut stdout, &findings, salt.is_some())?,
        Format::Sarif => report::render_sarif(&mut stdout, &findings)?,
    }
    let code = match fail_on {
        Some(sev) if findings.iter().any(|f| f.is_actionable() && f.severity >= sev) => 1,
        _ => 0,
    };
    Ok(code)
}

fn do_run(args: RunArgs) -> anyhow::Result<i32> {
    let mut plan = RunPlan {
        template: args.command.clone(),
        ..Default::default()
    };
    for spec in &args.secret_file {
        plan.add_spec(spec)?;
    }
    plan.validate()?;
    if args.dry_run {
        // Show the shape without touching the secrets.
        let mut masked = plan.template.clone();
        for name in plan.referenced() {
            for arg in masked.iter_mut() {
                *arg = arg.replace(&format!("{{{name}}}"), &format!("<{name}>"));
            }
        }
        println!("{}", run::suggested_command(&masked));
        return Ok(0);
    }
    // Never returns.
    run::run(&plan)?;
    unreachable!()
}

fn read_input(path: &str) -> anyhow::Result<String> {
    use std::io::Read;
    if path == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        Ok(s)
    } else {
        std::fs::read_to_string(path).with_context(|| format!("read {path}"))
    }
}

fn parse_sev(s: &str) -> anyhow::Result<Severity> {
    Severity::parse(s).ok_or_else(|| anyhow::anyhow!("unknown severity {s:?} (info|low|medium|high|critical)"))
}

fn well_known_roots(histories: bool) -> Vec<PathBuf> {
    let mut v = vec![
        PathBuf::from("/etc/cron.d"),
        PathBuf::from("/etc/cron.hourly"),
        PathBuf::from("/etc/cron.daily"),
        PathBuf::from("/etc/cron.weekly"),
        PathBuf::from("/etc/cron.monthly"),
        PathBuf::from("/var/spool/cron"),
        PathBuf::from("/var/spool/cron/crontabs"),
        PathBuf::from("/etc/systemd/system"),
        PathBuf::from("/lib/systemd/system"),
        PathBuf::from("/usr/lib/systemd/system"),
    ];
    if histories {
        v.push(PathBuf::from("/home"));
        v.push(PathBuf::from("/root"));
    }
    v
}
