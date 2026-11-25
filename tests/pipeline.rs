//! End-to-end contracts for the whole pipeline, through the public API.
//!
//! These are the properties that must never regress, because they are what
//! makes the tool safe to run on a fleet: no output path may ever print a
//! recoverable secret, and the distinctions that decide "is this a leak" must
//! keep holding.

use credops::collect::{self, audit, bpf, files};
use credops::model::{Finding, LocationRef, Severity, Surface};
use credops::remediate;
use credops::report;
use credops::run::{self, RunPlan};
use credops::scan::detect::{self, Context};
use std::collections::BTreeMap;
use std::path::PathBuf;

const SECRETS: &[&str] = &[
    "B4ckupPass!2024",
    "R3disAuth9",
    "SuperSecretEnvPass",
    "SuperSecretArgPass",
    "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
    "Ski9SecretToken",
    "PgS3cret!!",
    "Hunter2Secret",
    "OtherSecret9",
];

fn assert_no_secret_in(text: &str, what: &str) {
    for s in SECRETS {
        assert!(!text.contains(s), "{what} leaked {s:?}:\n{text}");
    }
}

fn ctx_for(path: &str, mode: u32) -> Context<'static> {
    Context::new(LocationRef::file(Surface::ScriptFile, path, 1, Some(mode)))
}

fn fleet() -> Vec<Finding> {
    let mut all = Vec::new();
    let scripts: &[(&str, &str, u32)] = &[
        (
            "/opt/backup.sh",
            "mysqldump -u backup -p'B4ckupPass!2024' production\nredis-cli -a R3disAuth9 ping\n",
            0o644,
        ),
        (
            "/etc/systemd/system/app.service",
            "Environment=\"DATABASE_PASSWORD=SuperSecretEnvPass\"\nExecStart=/usr/bin/mysql --password=SuperSecretArgPass\n",
            0o644,
        ),
        (
            "/home/app/.deploy.sh",
            "export DEPLOY_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz\ncurl -H \"Authorization: Bearer Ski9SecretToken\" https://x\npsql 'postgresql://app:PgS3cret!!@db/prod'\n",
            0o600,
        ),
        ("/home/app/.bash_history", "mysql -pHunter2Secret db\n", 0o600),
    ];
    for (path, text, mode) in scripts {
        let p = PathBuf::from(path);
        let syntax = files::Syntax::from_path(&p);
        all.extend(files::scan_text(text, &p, syntax, Some(*mode), Some("test-salt")));
    }
    let audit = concat!(
        "type=SYSCALL msg=audit(1.0:1): pid=9 uid=0 comm=\"mysqldump\" exe=\"/usr/bin/mysqldump\"\n",
        "type=EXECVE msg=audit(1.0:1): argc=2 a0=\"mysqldump\" a1=\"-pOtherSecret9\"\n"
    );
    all.extend(audit::scan_log(audit, Some("test-salt")));
    collect::dedup(all)
}

#[test]
fn every_renderer_masks_every_secret() {
    let findings = fleet();
    assert!(findings.len() >= 7, "{findings:#?}");

    let mut text = Vec::new();
    report::render_text(&mut text, &findings, Severity::Info).unwrap();
    assert_no_secret_in(&String::from_utf8(text).unwrap(), "text report");

    let mut json = Vec::new();
    report::render_json(&mut json, &findings, true).unwrap();
    assert_no_secret_in(&String::from_utf8(json).unwrap(), "json report");

    let mut sarif = Vec::new();
    report::render_sarif(&mut sarif, &findings).unwrap();
    assert_no_secret_in(&String::from_utf8(sarif).unwrap(), "sarif report");

    let mut rot = Vec::new();
    report::render_rotation(&mut rot, &findings).unwrap();
    assert_no_secret_in(&String::from_utf8(rot).unwrap(), "rotation checklist");

    let plan = remediate::build(&findings);
    let mut plan_text = Vec::new();
    report::render_plan(&mut plan_text, &plan).unwrap();
    assert_no_secret_in(&String::from_utf8(plan_text).unwrap(), "plan");
}

#[test]
fn the_same_credential_gets_one_fingerprint_across_hosts_and_forms() {
    let a = files::scan_text(
        "mysqldump -pB4ckupPass!2024 db",
        &PathBuf::from("/hostA/backup.sh"),
        files::Syntax::Shell,
        Some(0o644),
        Some("corp"),
    );
    let b = files::scan_text(
        "mysql --password=B4ckupPass!2024 -u app db",
        &PathBuf::from("/hostB/dump.sh"),
        files::Syntax::Shell,
        Some(0o644),
        Some("corp"),
    );
    assert_eq!(a[0].fingerprint, b[0].fingerprint);
    assert_eq!(a[0].fingerprint.len(), 16);
    // The salt must actually be in play.
    let unsalted = credops::model::fingerprint("B4ckupPass!2024", Some("other"));
    assert_ne!(a[0].fingerprint, unsalted);
}

#[test]
fn plan_never_proposes_to_keep_the_value_in_a_script() {
    let plan = remediate::build(&fleet());
    // Every static finding must be scheduled for removal from its file.
    let files_to_edit: Vec<&String> = plan.files.keys().collect();
    assert!(files_to_edit.iter().any(|f| f.contains("backup.sh")));
    assert!(files_to_edit.iter().any(|f| f.contains("app.service")));
    assert!(!plan.steps.is_empty());
    for s in &plan.steps {
        assert_no_secret_in(&s.snippet, "plan snippet");
        assert_no_secret_in(&s.action, "plan action");
    }
}

#[test]
fn reference_vs_expanded_is_the_whole_point() {
    // A script that reads a variable has no secret in it.
    let script = "mysql -u app -p\"$DB_PASS\" db";
    let fs = detect::scan_line(script, Surface::ScriptFile, &ctx_for("/opt/x.sh", 0o644));
    assert!(fs.is_empty(), "{fs:#?}");

    // The same text captured from argv means the shell already expanded it,
    // so the bytes in memory really are the password.
    let fs = detect::scan_line(script, Surface::ProcCmdline, &ctx_for("pid 1", 0o444));
    assert_eq!(fs.len(), 1, "{fs:#?}");
    assert_eq!(fs[0].severity, Severity::High);
}

#[test]
fn a_prompting_flag_is_not_a_leak_but_a_glued_value_is() {
    let prompt = detect::scan_line(
        "mysql -u app -p mydb",
        Surface::ScriptFile,
        &ctx_for("/opt/x.sh", 0o644),
    );
    assert!(prompt.iter().all(|f| !f.is_actionable()), "{prompt:#?}");

    let glued = detect::scan_line(
        "mysql -u app -pHunter2Secret mydb",
        Surface::ScriptFile,
        &ctx_for("/opt/x.sh", 0o644),
    );
    assert_eq!(glued.len(), 1);
    assert!(glued[0].is_actionable());
}

#[test]
fn audit_records_survive_as_findings_with_process_attribution() {
    let log = "type=SYSCALL msg=audit(5.0:9): pid=77 ppid=1 uid=0 comm=\"redis-cli\" exe=\"/usr/bin/redis-cli\"\n\
               type=EXECVE msg=audit(5.0:9): argc=3 a0=\"redis-cli\" a1=\"-a\" a2=\"R3disAuth9\"\n";
    let fs = audit::scan_log(log, None);
    assert_eq!(fs.len(), 1);
    assert_eq!(fs[0].location.surface, Surface::AuditLog);
    let p = fs[0].process.as_ref().unwrap();
    assert_eq!(p.pid, 77);
    assert_eq!(p.uid, Some(0));
    assert_eq!(p.exe.as_deref(), Some("/usr/bin/redis-cli"));
    assert_no_secret_in(&fs[0].context, "audit context");
}

#[test]
fn ebpf_feed_is_scanned_and_bad_lines_do_not_abort() {
    let feed = r#"{"pid":1,"comm":"mysql","argv":["mysql","-pHunter2Secret"]}
{bad json}
{"pid":2,"comm":"redis-cli","argv":["redis-cli","-a","OtherSecret9"]}
"#;
    let (events, bad) = bpf::parse_events(feed);
    assert_eq!(bad, 1);
    let fs = bpf::scan_events(&events, None);
    assert_eq!(fs.len(), 2);
    for f in &fs {
        assert_no_secret_in(&f.context, "ebpf context");
    }
}

#[test]
fn wrapper_round_trip_without_leaking_into_its_own_argv() {
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
    plan.add_spec("db=/tmp/credops-it-db.pass").unwrap();
    let mut map = BTreeMap::new();
    map.insert("db".to_string(), b"B4ckupPass!2024".to_vec());
    let argv = run::build_argv(&plan, &map).unwrap();
    assert_eq!(argv[4], "-pB4ckupPass!2024");
    // The wrapper's own command line (the template) never contains the value.
    assert_no_secret_in(&plan.template.join(" "), "wrapper argv");
}

#[test]
fn severity_tracks_who_can_read_the_source() {
    let mk = |path: &str, mode: u32| {
        files::scan_text(
            "mysqldump -pHunter2Secret db",
            &PathBuf::from(path),
            files::Syntax::Shell,
            Some(mode),
            None,
        )[0]
            .severity
    };
    let world = mk("/opt/shared.sh", 0o644);
    let owner = mk("/root/x.sh", 0o600);
    assert!(world > owner, "world={world:?} owner={owner:?}");

    // `scan_env` reports on the surface named by the location, so the caller
    // must say `environ`; `LocationRef::process` defaults to the cmdline.
    let mut loc = LocationRef::process(1);
    loc.surface = Surface::ProcEnv;
    let env = detect::scan_env("DATABASE_PASSWORD", "SuperSecretEnvPass", &Context::new(loc));
    // environ is owner/root readable, so it ranks below a world-readable file.
    assert!(env[0].severity < world);
}

#[test]
fn protected_forms_produce_no_actionable_findings() {
    let benign = [
        "mysql --defaults-extra-file=/etc/creds.cnf -u app db",
        "psql -h db -U app -w mydb",
        "curl -K /etc/curl.cfg https://x",
        "sshpass -f /run/secrets/pw ssh host",
        "openssl req -pass file:/run/secrets/x",
        "docker login --password-stdin registry",
        "export PGPASSFILE=/run/secrets/pgpass && psql -h db mydb",
    ];
    for line in benign {
        let fs = detect::scan_line(line, Surface::ScriptFile, &ctx_for("/opt/x.sh", 0o644));
        assert!(
            fs.iter().all(|f| !f.is_actionable()),
            "{line} -> {fs:#?}"
        );
    }
}
