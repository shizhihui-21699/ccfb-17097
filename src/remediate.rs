//! Turning findings into a migration plan.
//!
//! A plan is grouped by *where the fix happens*, not by finding, because that
//! is how the work is actually done: one script edit fixes several findings,
//! and one fleet-wide change (`hidepid=2`) fixes a whole class of them.
//!
//! The ordering is a policy, and it matters:
//!
//! 1. Stop the persistent leak first (rotate, then remove from files/history).
//! 2. Move each value to the best channel the tool supports.
//! 3. Only then narrow `/proc` for the residue that cannot be fixed.
//!
//! Doing 3 before 1 hides the problem without removing the copy in the
//! backup that will be restored next year.

use crate::model::{Channel, Finding, Remediation, Severity};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StepKind {
    /// Assume the value is already known to an attacker.
    Rotate,
    /// Remove from source files, history, logs.
    RemoveStatic,
    /// Move to a protected channel.
    ChangeChannel,
    /// Narrow who can read `/proc` at all.
    HardenHost,
    /// Verify the change took effect.
    Verify,
}

impl StepKind {
    pub fn label(&self) -> &'static str {
        match self {
            StepKind::Rotate => "rotate",
            StepKind::RemoveStatic => "remove-static",
            StepKind::ChangeChannel => "change-channel",
            StepKind::HardenHost => "harden-host",
            StepKind::Verify => "verify",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Step {
    pub kind: StepKind,
    /// Where the finding is (`/opt/backup.sh:12`, `pid 424`).
    pub location: String,
    pub surface: crate::model::Surface,
    pub severity: Severity,
    pub fingerprint: String,
    pub program: Option<String>,
    pub channel: Channel,
    pub action: String,
    pub snippet: String,
    pub residual: String,
    pub caveats: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Plan {
    pub steps: Vec<Step>,
    /// Distinct credential fingerprints, for the rotation checklist.
    pub distinct_credentials: usize,
    /// Scripts/jobs to edit, deduplicated.
    pub files: BTreeMap<String, Vec<String>>,
    /// Programs that accept the credential only in argv.
    pub argv_only: BTreeMap<String, usize>,
}

pub fn build(findings: &[Finding]) -> Plan {
    let mut plan = Plan::default();
    let mut seen_fp: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut ordered: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.is_actionable())
        .collect();
    ordered.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.location.display.cmp(&b.location.display))
    });

    for f in ordered {
        if !f.fingerprint.is_empty() {
            seen_fp.insert(f.fingerprint.clone());
        }
        let rem: Option<&Remediation> = f.remediation.as_ref();
        let channel = rem.map(|r| r.channel).unwrap_or(Channel::ProtectedFile);

        // 1. Rotation, once per static leak. A runtime-only sighting may be an
        // already-rotated value, so it is listed but not asserted.
        if f.location.surface.is_runtime() {
            plan.steps.push(step(
                StepKind::Rotate,
                f,
                channel,
                "assume this credential is compromised: anyone who ran `ps` could read it",
                "rotate at the source, then deploy the new value through the protected channel",
                "old value invalid",
                vec![],
            ));
        } else if matches!(
            f.location.surface,
            crate::model::Surface::ScriptFile
                | crate::model::Surface::CronEntry
                | crate::model::Surface::SystemdUnit
                | crate::model::Surface::HistoryFile
                | crate::model::Surface::ConfigFile
        ) {
            plan.steps.push(step(
                StepKind::Rotate,
                f,
                channel,
                "the value is stored in a file; treat it as disclosed",
                "rotate it, because removing it from the file does not undo copies in backups and VCS history",
                "old value invalid",
                vec![],
            ));
        }

        // 2. Remove the literal from static sources.
        if !f.location.surface.is_runtime() {
            let mut notes = vec![];
            if f.location.surface == crate::model::Surface::HistoryFile {
                notes.push(
                    "editing history only removes this copy; the real fix is to stop the command from writing the value"
                        .into(),
                );
            }
            plan.steps.push(step(
                StepKind::RemoveStatic,
                f,
                channel,
                "remove the literal value from this file",
                "replace the value with a placeholder, then apply the change below",
                "",
                notes,
            ));
            if let Some(file) = &f.location.file {
                plan.files
                    .entry(file.clone())
                    .or_default()
                    .push(f.location.display.clone());
            }
        }

        // 3. Move to a protected channel.
        plan.steps.push(step(
            StepKind::ChangeChannel,
            f,
            channel,
            rem.map(|r| r.action.as_str())
                .unwrap_or("move the credential out of argv"),
            rem.map(|r| r.snippet.as_str()).unwrap_or(""),
            rem.map(|r| r.residual.as_str()).unwrap_or(""),
            rem.map(|r| r.caveats.clone()).unwrap_or_default(),
        ));

        if channel == Channel::ArgvOnly {
            *plan.argv_only.entry(f.program.clone().unwrap_or_default()).or_insert(0) += 1;
        }
    }

    // 4. Host hardening, once, if there is any argv-only residue.
    if !plan.argv_only.is_empty() || findings.iter().any(|f| {
        f.is_actionable() && f.location.surface == crate::model::Surface::ProcCmdline
    }) {
        plan.steps.push(Step {
            kind: StepKind::HardenHost,
            location: "(host)".into(),
            surface: crate::model::Surface::Unknown,
            severity: Severity::Medium,
            fingerprint: String::new(),
            program: None,
            channel: Channel::ArgvOnly,
            action: "make /proc cmdline unreadable to unrelated users".into(),
            snippet: concat!(
                "# system-wide, for every unit:\n",
                "#   systemctl edit --global  ->  [Manager]\\nProtectProc=invisible\n",
                "# or remount:\n",
                "mount -o remount,hidepid=2 /proc\n",
                "# check:\n",
                "credops scan --proc   # as an unprivileged user; should see only your own pids"
            )
            .into(),
            residual: "cmdline readable only by the owning uid and root".into(),
            caveats: vec![
                "hidepid=2 changes behaviour for monitoring agents that read other users' /proc".into(),
                "the owning uid can still read its own argv, so a compromised service account still sees its own secrets".into(),
            ],
        });
    }

    plan.steps.push(Step {
        kind: StepKind::Verify,
        location: "(host)".into(),
        surface: crate::model::Surface::Unknown,
        severity: Severity::Info,
        fingerprint: String::new(),
        program: None,
        channel: Channel::None,
        action: "prove the leak is gone".into(),
        snippet: concat!(
            "# re-scan; expect no findings on surfaces you fixed:\n",
            "credops scan --all --fail-on high\n",
            "# and check that a peer user can no longer read a cmdline:\n",
            "sudo -u nobody cat /proc/$(pgrep -n mysqld)/cmdline"
        )
        .into(),
        residual: String::new(),
        caveats: vec![],
    });

    plan.steps.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then(b.severity.cmp(&a.severity))
            .then_with(|| a.location.cmp(&b.location))
    });
    plan.distinct_credentials = seen_fp.len();
    plan
}

fn step(
    kind: StepKind,
    f: &Finding,
    channel: Channel,
    action: &str,
    snippet: &str,
    residual: &str,
    caveats: Vec<String>,
) -> Step {
    Step {
        kind,
        location: f.location.display.clone(),
        surface: f.location.surface,
        severity: f.severity,
        fingerprint: f.fingerprint.clone(),
        program: f.program.clone(),
        channel,
        action: action.to_string(),
        snippet: snippet.to_string(),
        residual: residual.to_string(),
        caveats,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{LocationRef, Surface};
    use crate::scan::detect::{self, Context};

    fn findings(line: &str, surface: Surface, mode: Option<u32>) -> Vec<Finding> {
        let mut c = Context::new(LocationRef::file(surface, "/opt/backup.sh", 12, mode));
        c.location.surface = surface;
        detect::scan_line(line, surface, &c)
    }

    #[test]
    fn plan_orders_rotation_before_channel_change() {
        let fs = findings("mysql -pHunter2Secret db", Surface::ScriptFile, Some(0o644));
        let p = build(&fs);
        let rotate = p.steps.iter().position(|s| s.kind == StepKind::Rotate).unwrap();
        let change = p
            .steps
            .iter()
            .position(|s| s.kind == StepKind::ChangeChannel)
            .unwrap();
        assert!(rotate < change, "{:?}", p.steps.iter().map(|s| s.kind).collect::<Vec<_>>());
    }

    #[test]
    fn plan_counts_distinct_credentials_not_findings() {
        let mut all = findings("mysql -pHunter2Secret db", Surface::ScriptFile, Some(0o644));
        all.extend(findings(
            "mysqldump --password=Hunter2Secret db",
            Surface::CronEntry,
            Some(0o644),
        ));
        let p = build(&all);
        assert_eq!(p.distinct_credentials, 1);
    }

    #[test]
    fn static_leak_gets_rotate_remove_change() {
        let fs = findings("mysql -pHunter2Secret db", Surface::ScriptFile, Some(0o644));
        let p = build(&fs);
        let kinds: Vec<StepKind> = p.steps.iter().map(|s| s.kind).collect();
        assert!(kinds.contains(&StepKind::Rotate));
        assert!(kinds.contains(&StepKind::RemoveStatic));
        assert!(kinds.contains(&StepKind::ChangeChannel));
        assert!(p.files.contains_key("/opt/backup.sh"));
    }

    #[test]
    fn runtime_leak_gets_rotate_and_hardening() {
        let fs = findings("mysql -pHunter2Secret db", Surface::ProcCmdline, None);
        let p = build(&fs);
        let kinds: Vec<StepKind> = p.steps.iter().map(|s| s.kind).collect();
        assert!(kinds.contains(&StepKind::Rotate));
        assert!(kinds.contains(&StepKind::HardenHost));
        // The cmdline surface has no file to edit.
        assert!(!kinds.contains(&StepKind::RemoveStatic));
    }

    #[test]
    fn history_fix_has_a_caveat_about_the_real_cause() {
        let fs = findings("mysql -pHunter2Secret db", Surface::HistoryFile, Some(0o600));
        let p = build(&fs);
        let remove = p.steps.iter().find(|s| s.kind == StepKind::RemoveStatic).unwrap();
        assert!(remove.caveats.iter().any(|c| c.contains("real fix")));
    }

    #[test]
    fn plan_snapshot() {
        let fs = findings("mysql -pHunter2Secret db", Surface::ScriptFile, Some(0o644));
        let p = build(&fs);
        let text = format!("{} steps, {} credentials, {} files", p.steps.len(), p.distinct_credentials, p.files.len());
        assert_eq!(text, "4 steps, 1 credentials, 1 files");
    }
}
