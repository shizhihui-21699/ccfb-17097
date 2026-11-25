//! Rendering findings. Every renderer is safe to paste into a ticket: no
//! renderer prints a recoverable value.

use crate::model::{Channel, Finding, Severity};
use crate::remediate::Plan;
use std::io::Write;

pub fn render_text<W: Write>(
    out: &mut W,
    findings: &[Finding],
    min: Severity,
) -> std::io::Result<()> {
    let shown: Vec<&Finding> = findings.iter().filter(|f| f.severity >= min).collect();
    if shown.is_empty() {
        writeln!(out, "no findings at or above {min}")?;
        return Ok(());
    }
    let mut by_loc: Vec<&&Finding> = shown.iter().collect();
    by_loc.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.location.display.cmp(&b.location.display))
            .then_with(|| a.span.start.cmp(&b.span.start))
    });

    writeln!(
        out,
        "{} finding(s) at or above {}\n",
        shown.len(),
        min
    )?;
    for f in by_loc {
        writeln!(
            out,
            "{:<8} {:<10} {:<22} {}",
            f.severity.to_string().to_uppercase(),
            f.kind.label(),
            f.location.surface.label(),
            f.location.display
        )?;
        if let Some(key) = &f.key {
            writeln!(out, "         key:        {key}")?;
        }
        writeln!(
            out,
            "         detector:   {} (confidence {})",
            f.detector, f.confidence
        )?;
        writeln!(out, "         value:      {} len={}", f.preview, f.value_len)?;
        if !f.fingerprint.is_empty() {
            writeln!(out, "         fingerprint:{}", f.fingerprint)?;
        }
        if !f.context.is_empty() {
            writeln!(out, "         context:    {}", f.context)?;
        }
        if let Some(p) = &f.process {
            if p.pid != 0 {
                writeln!(
                    out,
                    "         process:    pid {} uid {} {}",
                    p.pid,
                    p.uid.map(|u| u.to_string()).unwrap_or_else(|| "?".into()),
                    p.comm.clone().unwrap_or_default()
                )?;
                if !p.ancestors.is_empty() {
                    let chain: Vec<String> = p
                        .ancestors
                        .iter()
                        .take(4)
                        .map(|a| format!("{}[{}]", a.comm, a.pid))
                        .collect();
                    writeln!(out, "         ancestry:   {}", chain.join(" <- "))?;
                }
            }
        }
        for n in f.notes.iter().take(3) {
            writeln!(out, "         note:       {n}")?;
        }
        if let Some(r) = &f.remediation {
            writeln!(out, "         fix:        [{}] {}", r.channel.label(), r.action)?;
            writeln!(out, "         residual:   {}", r.residual)?;
        }
        writeln!(out)?;
    }
    Ok(())
}

pub fn render_plan<W: Write>(out: &mut W, plan: &Plan) -> std::io::Result<()> {
    writeln!(
        out,
        "migration plan: {} distinct credential(s), {} file(s) to edit, {} step(s)",
        plan.distinct_credentials,
        plan.files.len(),
        plan.steps.len()
    )?;
    if !plan.files.is_empty() {
        writeln!(out, "\nfiles to edit:")?;
        for (file, locs) in &plan.files {
            writeln!(out, "  {file}  ({} finding(s))", locs.len())?;
        }
    }
    if !plan.argv_only.is_empty() {
        writeln!(out, "\ntools that accept the credential only in argv:")?;
        for (prog, n) in &plan.argv_only {
            writeln!(out, "  {prog}: {n} occurrence(s)")?;
        }
    }
    writeln!(out)?;
    let mut last_kind = None;
    for s in &plan.steps {
        if last_kind != Some(s.kind) {
            writeln!(out, "## {}", s.kind.label())?;
            last_kind = Some(s.kind);
        }
        writeln!(out, "- {} [{}]", s.location, s.surface.label())?;
        writeln!(out, "  {}", s.action)?;
        if !s.snippet.is_empty() {
            for line in s.snippet.lines() {
                writeln!(out, "    {line}")?;
            }
        }
        for c in &s.caveats {
            writeln!(out, "  ! {c}")?;
        }
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct JsonReport<'a> {
    schema: &'static str,
    generated_by: &'static str,
    findings: Vec<&'a Finding>,
    summary: Summary,
}

#[derive(serde::Serialize)]
struct Summary {
    total: usize,
    actionable: usize,
    by_severity: std::collections::BTreeMap<String, usize>,
    by_surface: std::collections::BTreeMap<String, usize>,
    by_channel: std::collections::BTreeMap<String, usize>,
    distinct_credentials: usize,
}

pub fn render_json<W: Write>(out: &mut W, findings: &[Finding], salt_note: bool) -> std::io::Result<()> {
    let mut by_severity = std::collections::BTreeMap::new();
    let mut by_surface = std::collections::BTreeMap::new();
    let mut by_channel = std::collections::BTreeMap::new();
    let mut fps = std::collections::BTreeSet::new();
    for f in findings {
        *by_severity.entry(f.severity.to_string()).or_insert(0) += 1;
        *by_surface
            .entry(f.location.surface.label().to_string())
            .or_insert(0) += 1;
        let ch = f
            .remediation
            .as_ref()
            .map(|r| r.channel)
            .unwrap_or(Channel::None);
        *by_channel.entry(ch.label().to_string()).or_insert(0) += 1;
        if !f.fingerprint.is_empty() {
            fps.insert(f.fingerprint.clone());
        }
    }
    let report = JsonReport {
        schema: "credops.report.v1",
        generated_by: if salt_note {
            "credops (salted fingerprints)"
        } else {
            "credops (UNSALTED fingerprints: do not share)"
        },
        findings: findings.iter().collect(),
        summary: Summary {
            total: findings.len(),
            actionable: findings.iter().filter(|f| f.is_actionable()).count(),
            by_severity,
            by_surface,
            by_channel,
            distinct_credentials: fps.len(),
        },
    };
    serde_json::to_writer_pretty(&mut *out, &report)?;
    writeln!(out)
}

/// Machine-readable SARIF, for CI systems that already ingest it.
pub fn render_sarif<W: Write>(out: &mut W, findings: &[Finding]) -> std::io::Result<()> {
    let results: Vec<serde_json::Value> = findings
        .iter()
        .filter(|f| f.is_actionable())
        .map(|f| {
            let level = match f.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                _ => "note",
            };
            let mut msg = format!(
                "{} exposed in {}",
                f.kind.label(),
                f.location.surface.label()
            );
            if let Some(k) = &f.key {
                msg.push_str(&format!(" via {k}"));
            }
            msg.push_str(&format!("; value masked as {}", f.preview));
            if let Some(r) = &f.remediation {
                msg.push_str(&format!(". Fix: {}", r.action));
            }
            serde_json::json!({
                "ruleId": f.detector.replace(':', "-"),
                "level": level,
                "message": { "text": msg },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.location.file.clone().unwrap_or_else(|| f.location.display.clone())
                        },
                        "region": { "startLine": f.location.line.unwrap_or(1) }
                    }
                }],
                "partialFingerprints": { "credopsFingerprint": f.fingerprint }
            })
        })
        .collect();
    let doc = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "credops",
                "informationUri": "https://example.invalid/credops",
                "rules": []
            }},
            "results": results
        }]
    });
    serde_json::to_writer_pretty(&mut *out, &doc)?;
    writeln!(out)
}

/// A rotation checklist: one line per distinct credential, identified only by
/// fingerprint and the places it was seen.
pub fn render_rotation<W: Write>(out: &mut W, findings: &[Finding]) -> std::io::Result<()> {
    let mut by_fp: std::collections::BTreeMap<&str, Vec<&Finding>> = std::collections::BTreeMap::new();
    for f in findings.iter().filter(|f| !f.fingerprint.is_empty() && f.is_actionable()) {
        by_fp.entry(&f.fingerprint).or_default().push(f);
    }
    writeln!(
        out,
        "rotation checklist: {} credential(s) to rotate\n",
        by_fp.len()
    )?;
    for (i, (fp, group)) in by_fp.iter().enumerate() {
        let first = group[0];
        writeln!(
            out,
            "{}. {} [{}] fingerprint {} ({} occurrence(s))",
            i + 1,
            first.kind.label(),
            first.preview,
            fp,
            group.len()
        )?;
        writeln!(out, "   rotate: change it at the issuer, not just in the file")?;
        for f in group.iter().take(8) {
            writeln!(out, "   seen:   {} ({})", f.location.display, f.location.surface.label())?;
        }
        if group.len() > 8 {
            writeln!(out, "   ... and {} more", group.len() - 8)?;
        }
        writeln!(out)?;
    }
    Ok(())
}

/// Priorities for a report footer.
pub fn headline(findings: &[Finding]) -> String {
    let actionable: Vec<&Finding> = findings.iter().filter(|f| f.is_actionable()).collect();
    let crit = actionable
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = actionable
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let fps: std::collections::BTreeSet<&str> = actionable
        .iter()
        .map(|f| f.fingerprint.as_str())
        .filter(|s| !s.is_empty())
        .collect();
    format!(
        "{} finding(s), {} critical, {} high, {} distinct credential(s) to rotate",
        actionable.len(),
        crit,
        high,
        fps.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::LocationRef;
    use crate::model::Surface;
    use crate::scan::detect::{self, Context};

    fn sample() -> Vec<Finding> {
        let c = Context::new(LocationRef::file(Surface::ScriptFile, "/opt/b.sh", 3, Some(0o644)));
        detect::scan_line("mysql -pHunter2Secret db", Surface::ScriptFile, &c)
    }

    #[test]
    fn text_renderer_never_prints_the_secret() {
        let fs = sample();
        let mut buf = Vec::new();
        render_text(&mut buf, &fs, Severity::Info).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(!s.contains("Hunter2Secret"), "{s}");
        assert!(s.contains("mysql"), "{s}");
        assert!(s.contains("tool:mysql:-p"), "{s}");
    }

    #[test]
    fn json_renderer_never_prints_the_secret() {
        let fs = sample();
        let mut buf = Vec::new();
        render_json(&mut buf, &fs, true).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(!s.contains("Hunter2Secret"), "{s}");
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["summary"]["total"], 1);
        assert_eq!(v["schema"], "credops.report.v1");
    }

    #[test]
    fn sarif_is_valid_json_and_masked() {
        let fs = sample();
        let mut buf = Vec::new();
        render_sarif(&mut buf, &fs).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(!s.contains("Hunter2Secret"));
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn plan_renderer_is_readable() {
        let fs = sample();
        let plan = crate::remediate::build(&fs);
        let mut buf = Vec::new();
        render_plan(&mut buf, &plan).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(!s.contains("Hunter2Secret"));
        assert!(s.contains("## rotate"));
        assert!(s.contains("## change-channel"));
    }

    #[test]
    fn rotation_checklist_groups_by_fingerprint() {
        let mut fs = sample();
        fs.extend(sample()); // same value twice
        let mut buf = Vec::new();
        render_rotation(&mut buf, &fs).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("1 credential(s) to rotate"), "{s}");
        assert!(!s.contains("Hunter2Secret"));
    }

    #[test]
    fn headline_counts() {
        let fs = sample();
        let h = headline(&fs);
        assert!(h.contains("1 finding"), "{h}");
        assert!(h.contains("1 distinct credential"), "{h}");
    }

    #[test]
    fn step_kind_label_exists() {
        assert_eq!(crate::remediate::StepKind::Rotate.label(), "rotate");
    }
}
