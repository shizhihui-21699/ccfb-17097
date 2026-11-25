//! Credential detection over command lines, environment and text.
//!
//! Layered on purpose, because each layer has a different failure mode:
//!
//! 1. **Tool rules** from [`super::knowledge`] — high precision, low recall.
//!    These get the spelling right (`mysql -pX` vs `mysql -p`), which matters
//!    more than breadth: a noisy scanner is a scanner nobody runs.
//! 2. **Key heuristics** — `--db_password=x`, `DB_PASS=x`, `password: x`.
//!    Catches the long tail of home-grown scripts.
//! 3. **Value patterns** — `AKIA...`, `ghp_...`, JWTs, private-key blocks.
//!    Catches credentials whose key name says nothing.
//! 4. **Reference and placeholder filters** — the layer that stops the tool
//!    from reporting `$DB_PASS`, `file:/run/secrets/x` and `changeme` as leaks.
//!    Together with 1, this is what makes the output trustworthy.

use crate::model::{preview, redact_spans, Channel, Confidence, Finding, SecretKind, Severity, Span};
use crate::scan::knowledge::{self, ArgRule, Form, KeyClass, ToolSpec};
use crate::scan::sh::{self, split_kv, SimpleCommand, Token};
use regex::Regex;
use std::sync::OnceLock;

#[derive(Clone, Default)]
pub struct Context<'a> {
    pub location: crate::model::LocationRef,
    pub process: Option<crate::model::ProcessRef>,
    pub salt: Option<&'a str>,
}

impl<'a> Context<'a> {
    pub fn new(location: crate::model::LocationRef) -> Self {
        Context {
            location,
            process: None,
            salt: None,
        }
    }
}

/// Scan one already-split command line (NUL-joined cmdline, a script line, a
/// crontab line, ...).
pub fn scan_line(raw: &str, surface: crate::model::Surface, ctx: &Context<'_>) -> Vec<Finding> {
    let mut found: Vec<Finding> = Vec::new();
    let mut loc = ctx.location.clone();
    loc.surface = surface;

    let commands = sh::lex_line(raw);
    for cmd in &commands {
        if let Some((program, _)) = cmd.effective_program() {
            if let Some(spec) = knowledge::find_tool(&program) {
                scan_tool_command(cmd, spec, raw, surface, ctx, &mut found);
            }
        }
        scan_generic_command(cmd, raw, surface, ctx, &mut found);
    }
    scan_value_patterns(raw, surface, ctx, &mut found);
    finalize(found, raw)
}

/// Scan a single `NAME=value` environment pair.
pub fn scan_env(name: &str, value: &str, ctx: &Context<'_>) -> Vec<Finding> {
    let mut found = Vec::new();
    let loc = ctx.location.clone();

    if name.eq_ignore_ascii_case("LS_COLORS") || name.eq_ignore_ascii_case("PATH") {
        return found;
    }

    let value_start = 0usize;
    let class = classify_value(value, false);
    let rule = knowledge::env_rule(name);

    if let Some(rule) = rule {
        if rule.recommended {
            found.push(build(
                ctx,
                &Build {
                    kind: rule.kind,
                    detector: format!("env:{}", rule.name),
                    surface: loc.surface,
                    span: Span::new(value_start, value.len()),
                    value,
                    key: Some(name.to_string()),
                    program: None,
                    conf: Confidence::Certain,
                    base: Severity::Info,
                    remediation: None,
                    notes: vec![format!(
                        "{} is a protected channel for this tool; the value is not in any command line",
                        rule.name
                    )],
                    loc: loc.clone(),
                },
            ));
            return found;
        }
        // The variable's name is authoritative for what it holds; the value's
        // shape only affects confidence and severity, both handled in `build`.
        let kind = rule.kind;
        found.push(build(
            ctx,
            &Build {
                kind,
                detector: format!("env:{}", rule.name),
                surface: loc.surface,
                span: Span::new(value_start, value.len()),
                value,
                key: Some(name.to_string()),
                program: None,
                conf: Confidence::Certain,
                base: base_severity(kind),
                remediation: Some(generic_remediation(kind, Channel::ProtectedFile, None)),
                notes: Vec::new(),
                loc: loc.clone(),
            },
        ));
        return found;
    }

    match knowledge::key_sensitivity(name) {
        KeyClass::Strong | KeyClass::Weak => {
            if class != ValueClass::Literal {
                return found;
            }
            let conf = if knowledge::key_sensitivity(name) == KeyClass::Strong {
                Confidence::High
            } else {
                Confidence::Medium
            };
            let kind = kind_from_key(name);
            found.push(build(
                ctx,
                &Build {
                    kind,
                    detector: "env:key-name".to_string(),
                    surface: loc.surface,
                    span: Span::new(value_start, value.len()),
                    value,
                    key: Some(name.to_string()),
                    program: None,
                    conf,
                    base: base_severity(kind),
                    remediation: Some(generic_remediation(kind, Channel::ProtectedFile, None)),
                    notes: Vec::new(),
                    loc: loc.clone(),
                },
            ));
        }
        KeyClass::Reference | KeyClass::None => {
            // Still catch embedded well-known credentials in a neutral var.
            if class == ValueClass::Literal {
                for f in scan_value_patterns(value, loc.surface, ctx, &mut Vec::new()) {
                    let mut f = f;
                    f.key = Some(name.to_string());
                    if let Some(p) = &ctx.process {
                        f.process = Some(p.clone());
                    }
                    found.push(f);
                }
            }
        }
    }
    found
}

fn scan_tool_command(
    cmd: &SimpleCommand,
    spec: &'static ToolSpec,
    raw: &str,
    surface: crate::model::Surface,
    ctx: &Context<'_>,
    out: &mut Vec<Finding>,
) {
    let toks = &cmd.tokens;
    let start = cmd.argv_start.unwrap_or(0);

    for (idx, tok) in toks.iter().enumerate() {
        if idx < start || tok.is_redirect {
            continue;
        }
        for rule in spec.rules {
            match *rule {
                ArgRule::Attached { prefix, kind, require_value } => {
                    if !tok.text.starts_with(prefix) || tok.text.starts_with("--") {
                        continue;
                    }
                    let rest = &tok.text[prefix.len()..];
                    if rest.is_empty() {
                        if !require_value {
                            continue;
                        }
                        // `mysql -p` prompts; that is the safe spelling.
                        out.push(note_only(
                            ctx,
                            surface,
                            tok.span,
                            format!(
                                "{} {} prompts for the password interactively",
                                spec.name, prefix
                            ),
                        ));
                        continue;
                    }
                    // `-port=3306` is a long option, not `-p ort=3306`.
                    if let Some(eq) = rest.find('=') {
                        let head = &rest[..eq];
                        if head.len() >= 3 && head.bytes().all(|b| b.is_ascii_lowercase()) {
                            continue;
                        }
                    }
                    let vspan = Span::new(prefix.len(), tok.text.len());
                    emit_value(
                        out, ctx, surface, spec, tok, raw, vspan, kind,
                        format!("tool:{}:{}", spec.name, prefix),
                        Some(prefix.to_string()),
                        Confidence::Certain,
                        Some(&spec.migration),
                        Vec::new(),
                    );
                }
                ArgRule::Flag { flag, form, kind } => {
                    // `--flag=value`
                    if form != Form::Separate {
                        let with_eq = format!("{flag}=");
                        if let Some(rest) = tok.text.strip_prefix(&with_eq) {
                            if rest.is_empty() {
                                continue;
                            }
                            let vspan = Span::new(with_eq.len(), tok.text.len());
                            emit_value(
                                out, ctx, surface, spec, tok, raw, vspan, kind,
                                format!("tool:{}:{}", spec.name, flag),
                                Some(flag.to_string()),
                                Confidence::Certain,
                                Some(&spec.migration),
                                Vec::new(),
                            );
                            continue;
                        }
                    }
                    // A short option with a glued value: `-aVALUE`, `-pSecret`.
                    if form != Form::Equals
                        && flag.len() == 2
                        && flag.starts_with('-')
                        && !flag.starts_with("--")
                        && tok.text.starts_with(flag)
                        && tok.text.len() > flag.len()
                        && !tok.text[flag.len()..].starts_with('=')
                    {
                        let vspan = Span::new(flag.len(), tok.text.len());
                        emit_value(
                            out, ctx, surface, spec, tok, raw, vspan, kind,
                            format!("tool:{}:{}", spec.name, flag),
                            Some(flag.to_string()),
                            Confidence::Certain,
                            Some(&spec.migration),
                            Vec::new(),
                        );
                        continue;
                    }
                    // `--flag value` (or `-a value`)
                    if form != Form::Equals && tok.text == flag {
                        if let Some(next) = toks.get(idx + 1) {
                            if next.is_redirect || next.text.starts_with('-') {
                                continue;
                            }
                            let vspan = Span::new(0, next.text.len());
                            emit_value(
                                out, ctx, surface, spec, next, raw, vspan, kind,
                                format!("tool:{}:{}", spec.name, flag),
                                Some(flag.to_string()),
                                Confidence::Certain,
                                Some(&spec.migration),
                                Vec::new(),
                            );
                        }
                    }
                }
                ArgRule::UserInfo { flag, kind } => {
                    let val = if tok.text == flag {
                        toks.get(idx + 1).map(|t| (t, 0usize))
                    } else {
                        tok.text
                            .strip_prefix(&format!("{flag}="))
                            .map(|_| (tok, flag.len() + 1))
                    };
                    let Some((vtok, off)) = val else { continue };
                    let rel = &vtok.text[off..];
                    if let Some(colon) = rel.find(':') {
                        let vspan = Span::new(off + colon + 1, vtok.text.len());
                        emit_value(
                            out, ctx, surface, spec, vtok, raw, vspan, kind,
                            format!("tool:{}:{}", spec.name, flag),
                            Some(flag.to_string()),
                            Confidence::Certain,
                            Some(&spec.migration),
                            Vec::new(),
                        );
                    }
                }
                ArgRule::UrlUserInfo => {
                    // Handled by the value-pattern layer, which sees the whole
                    // URL including its scheme; nothing to do per token.
                }
                ArgRule::PercentUserPass { flag } => {
                    let val = if tok.text == flag {
                        toks.get(idx + 1).map(|t| (t, 0usize))
                    } else {
                        tok.text
                            .strip_prefix(&format!("{flag}="))
                            .map(|_| (tok, flag.len() + 1))
                    };
                    let Some((vtok, off)) = val else { continue };
                    if let Some(pct) = vtok.text[off..].find('%') {
                        let vspan = Span::new(off + pct + 1, vtok.text.len());
                        emit_value(
                            out, ctx, surface, spec, vtok, raw, vspan, SecretKind::Password,
                            format!("tool:{}:{}", spec.name, flag),
                            Some(flag.to_string()),
                            Confidence::Certain,
                            Some(&spec.migration),
                            Vec::new(),
                        );
                    }
                }
                ArgRule::CommaUserPass { flag } => {
                    let val = if tok.text == flag {
                        toks.get(idx + 1).map(|t| (t, 0usize))
                    } else {
                        tok.text
                            .strip_prefix(&format!("{flag}="))
                            .map(|_| (tok, flag.len() + 1))
                    };
                    let Some((vtok, off)) = val else { continue };
                    if let Some(comma) = vtok.text[off..].find(',') {
                        let vspan = Span::new(off + comma + 1, vtok.text.len());
                        emit_value(
                            out, ctx, surface, spec, vtok, raw, vspan, SecretKind::Password,
                            format!("tool:{}:{}", spec.name, flag),
                            Some(flag.to_string()),
                            Confidence::Certain,
                            Some(&spec.migration),
                            Vec::new(),
                        );
                    }
                }
                ArgRule::PassSpec { flag } => {
                    if tok.text != flag {
                        continue;
                    }
                    let Some(next) = toks.get(idx + 1) else { continue };
                    if let Some(rest) = next.text.strip_prefix("pass:") {
                        let vspan = Span::new("pass:".len(), next.text.len());
                        emit_value(
                            out, ctx, surface, spec, next, raw, vspan, SecretKind::Password,
                            format!("tool:{}:{}", spec.name, flag),
                            Some(flag.to_string()),
                            Confidence::Certain,
                            Some(&spec.migration),
                            Vec::new(),
                        );
                        let _ = rest;
                    }
                }
                ArgRule::AuthHeader { flag } => {
                    let val = if tok.text == flag {
                        toks.get(idx + 1)
                    } else if tok.text.starts_with(&format!("{flag}=")) {
                        Some(tok)
                    } else {
                        None
                    };
                    let Some(vtok) = val else { continue };
                    scan_auth_header(out, ctx, surface, spec, vtok, raw);
                }
                ArgRule::ExtraVars { flag } => {
                    // `--extra-vars k=v` and `--extra-vars=k=v` are both valid.
                    if tok.text == flag {
                        let Some(next) = toks.get(idx + 1) else { continue };
                        if next.text.starts_with('@') {
                            continue; // `@file` is the protected form
                        }
                        scan_kv_pairs_in_word(out, ctx, surface, spec, next, raw);
                    } else if let Some(rest) = tok.text.strip_prefix(&format!("{flag}=")) {
                        if !rest.starts_with('@') {
                            let offset = flag.len() + 1;
                            scan_kv_pairs_at(out, ctx, surface, spec, tok, raw, offset);
                        }
                    }
                }
                ArgRule::LastPositional { flag } => {
                    let has = toks.iter().any(|t| t.text == flag);
                    if !has {
                        continue;
                    }
                    // Only the final non-option token is the secret.
                    if let Some(last) = toks
                        .iter()
                        .rev()
                        .find(|t| !t.is_redirect && !t.text.starts_with('-'))
                    {
                        if std::ptr::eq(last, tok) {
                            let vspan = Span::new(0, tok.text.len());
                            emit_value(
                                out, ctx, surface, spec, tok, raw, vspan, SecretKind::Password,
                                format!("tool:{}:{}", spec.name, flag),
                                Some(flag.to_string()),
                                Confidence::High,
                                Some(&spec.migration),
                                vec!["the trailing positional is only a password when -b is present".into()],
                            );
                        }
                    }
                }
            }
        }
    }
    let _ = raw;
}

fn scan_auth_header(
    out: &mut Vec<Finding>,
    ctx: &Context<'_>,
    surface: crate::model::Surface,
    spec: &'static ToolSpec,
    tok: &Token,
    raw: &str,
) {
    let Some(colon) = tok.text.find(':') else { return };
    let header = tok.text[..colon].trim().to_ascii_lowercase();
    let sensitive = matches!(
        header.as_str(),
        "authorization" | "proxy-authorization" | "x-api-key" | "x-auth-token"
            | "x-access-token" | "x-gitlab-token" | "private-token" | "privatetoken"
    );
    if !sensitive {
        return;
    }
    let mut vstart = colon + 1;
    let rest = &tok.text[vstart..];
    let trimmed = rest.trim_start();
    vstart += rest.len() - trimmed.len();
    // Strip an auth scheme word: `Bearer xyz`, `Basic base64`.
    let value = &tok.text[vstart..];
    let mut vs = vstart;
    if let Some((scheme, after)) = value.split_once(' ') {
        if !scheme.is_empty()
            && scheme.len() <= 10
            && scheme.chars().all(|c| c.is_ascii_alphabetic())
            && !after.trim().is_empty()
        {
            vs += scheme.len();
            let rest2 = &tok.text[vs..];
            let trimmed2 = rest2.trim_start();
            vs += rest2.len() - trimmed2.len();
        }
    }
    if vs >= tok.text.len() {
        return;
    }
    emit_value(
        out, ctx, surface, spec, tok, raw, Span::new(vs, tok.text.len()),
        SecretKind::Token,
        format!("tool:{}:auth-header", spec.name),
        Some(header),
        Confidence::High,
        Some(&spec.migration),
        Vec::new(),
    );
}

/// `--extra-vars 'db_password=x api_key=y'`
fn scan_kv_pairs_in_word(
    out: &mut Vec<Finding>,
    ctx: &Context<'_>,
    surface: crate::model::Surface,
    spec: &'static ToolSpec,
    tok: &Token,
    raw: &str,
) {
    scan_kv_pairs_at(out, ctx, surface, spec, tok, raw, 0);
}

fn scan_kv_pairs_at(
    out: &mut Vec<Finding>,
    ctx: &Context<'_>,
    surface: crate::model::Surface,
    spec: &'static ToolSpec,
    tok: &Token,
    raw: &str,
    from: usize,
) {
    let body = &tok.text[from..];
    let mut cursor = 0usize;
    for part in body.split_whitespace() {
        let Some(rel) = body[cursor..].find(part) else { continue };
        let pos = from + cursor + rel;
        cursor = cursor + rel + part.len();
        if let Some((key, vstart)) = split_kv(part) {
            if knowledge::key_sensitivity(key) == KeyClass::Strong {
                let vspan = Span::new(pos + vstart, pos + part.len());
                emit_value(
                    out, ctx, surface, spec, tok, raw, vspan, kind_from_key(key),
                    format!("tool:{}:extra-vars", spec.name),
                    Some(key.trim_start_matches('-').to_string()),
                    Confidence::High,
                    Some(&spec.migration),
                    Vec::new(),
                );
            }
        }
    }
}

/// Generic key-based detection over every token of a command.
fn scan_generic_command(
    cmd: &SimpleCommand,
    raw: &str,
    surface: crate::model::Surface,
    ctx: &Context<'_>,
    out: &mut Vec<Finding>,
) {
    let start = cmd.argv_start.unwrap_or(0);
    for (idx, tok) in cmd.tokens.iter().enumerate() {
        if tok.is_redirect {
            continue;
        }
        // `NAME=value` prefix (env assignment for the command). These sit
        // *before* the command word, so they are checked before the
        // argv-position filter below. A quoted token holding several pairs is
        // a payload, handled by the tool rule instead.
        if !tok.text.chars().any(char::is_whitespace) {
            if let Some(eq) = sh::assignment_split(&tok.text) {
                let key = &tok.text[..eq];
                let vstart = eq + 1;
                if knowledge::key_sensitivity(key) == KeyClass::Strong {
                    emit_generic_value(
                        out, ctx, surface, tok, raw,
                        Span::new(vstart, tok.text.len()),
                        key, "cmdline:assignment", Confidence::High,
                    );
                }
                continue;
            }
        }
        if idx < start {
            continue;
        }
        // A quoted token holding several `k=v` pairs (ansible-style) is not a
        // single option; treating it as one would produce a span covering
        // every pair and hide the precise findings.
        if tok.text.chars().any(char::is_whitespace) {
            continue;
        }
        // `--key=value` / `key: value`
        if let Some((key, vstart)) = split_kv(&tok.text) {
            // `--flag=value` is a normal option. `key=value` is only an
            // assignment when `key` is an identifier, and that case was
            // already handled by `assignment_split` above.
            let is_option = key.starts_with('-');
            let is_ident = sh::assignment_split(&format!("{key}=x")).is_some();
            if is_option || is_ident {
                let vspan = Span::new(vstart, tok.text.len());
                match knowledge::key_sensitivity(key) {
                    KeyClass::Strong => emit_generic_value(
                        out, ctx, surface, tok, raw, vspan, key, "cmdline:option",
                        Confidence::High,
                    ),
                    // A bare `key`/`signing-key` needs the value to look secret
                    // as well; the entropy floor is applied inside emit_generic_value.
                    KeyClass::Weak => {
                        let v = tok.text.get(vspan.start..vspan.end).unwrap_or("");
                        if looks_entropic(v) && v.len() >= 8 {
                            emit_generic_value(
                                out, ctx, surface, tok, raw, vspan, key,
                                "cmdline:option-weak", Confidence::Low,
                            );
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_generic_value(
    out: &mut Vec<Finding>,
    ctx: &Context<'_>,
    surface: crate::model::Surface,
    tok: &Token,
    raw: &str,
    text_span: Span,
    key: &str,
    detector: &str,
    conf: Confidence,
) {
    // A weak key (e.g. `--key`) only counts when the value really looks secret.
    if conf == Confidence::Low && !looks_entropic(tok.text.get(text_span.start..text_span.end).unwrap_or("")) {
        return;
    }
    let kind = kind_from_key(key);
    emit_value(
        out, ctx, surface, &NO_SPEC, tok, raw, text_span, kind,
        detector.to_string(),
        Some(key.trim_start_matches('-').to_string()),
        conf,
        None,
        Vec::new(),
    );
}

/// Placeholder for tools we do not know: carries no migration.
static NO_SPEC: ToolSpec = ToolSpec {
    name: "",
    aliases: &[],
    provider: None,
    rules: &[],
    env: &[],
    migration: knowledge::Migration {
        channel: Channel::None,
        snippet: "",
        caveats: &[],
        residual: "",
    },
};

#[allow(clippy::too_many_arguments)]
fn emit_value(
    out: &mut Vec<Finding>,
    ctx: &Context<'_>,
    surface: crate::model::Surface,
    spec: &'static ToolSpec,
    tok: &Token,
    raw: &str,
    text_span: Span,
    kind: SecretKind,
    detector: String,
    key: Option<String>,
    conf: Confidence,
    migration: Option<&'static knowledge::Migration>,
    mut notes: Vec<String>,
) {
    if text_span.start > text_span.end || text_span.end > tok.text.len() {
        return;
    }
    let value = &tok.text[text_span.start..text_span.end];
    let class = classify_value(value, tok.substitution);
    let raw_span = tok.to_raw(text_span);
    let mut base = base_severity(kind);
    let mut conf = conf;
    match class {
        ValueClass::Literal => {}
        ValueClass::Reference => {
            if !surface.is_expanded() {
                // A reference in a static file: the file is not the leak.
                return;
            }
            // In argv/env the shell already expanded it, so `$X` is the literal.
            notes.push("looks like a variable reference but was captured after expansion".into());
            conf = Confidence::Medium;
        }
        ValueClass::Placeholder => {
            base = Severity::Info;
            notes.push("value is a placeholder, not a real credential".into());
        }
        ValueClass::Empty => return,
    }
    if value.len() < min_len_for(kind, conf) {
        return;
    }
    if !tok.text.is_char_boundary(text_span.start) || !tok.text.is_char_boundary(text_span.end) {
        return;
    }
    let remediation = migration
        .map(|m| remediation_from(m, spec, kind, surface))
        .or_else(|| Some(generic_remediation(kind, Channel::ProtectedFile, None)));
    let mut l = ctx.location.clone();
    l.surface = surface;
    out.push(build(
        ctx,
        &Build {
            kind,
            detector,
            surface,
            span: raw_span,
            value,
            key,
            program: if spec.name.is_empty() { None } else { Some(spec.name.to_string()) },
            conf,
            base,
            remediation,
            notes,
            loc: l,
        },
    ));
    let _ = raw;
}

fn note_only(
    ctx: &Context<'_>,
    surface: crate::model::Surface,
    span: Span,
    note: String,
) -> Finding {
    let mut l = ctx.location.clone();
    l.surface = surface;
    let mut f = build(
        ctx,
        &Build {
            kind: SecretKind::Password,
            detector: "note:prompt".into(),
            surface,
            span,
            value: "",
            key: None,
            program: None,
            conf: Confidence::Certain,
            base: Severity::Info,
            remediation: None,
            notes: vec![note],
            loc: l,
        },
    );
    f.suppressed = true;
    f.preview = String::new();
    f
}

struct Build<'a> {
    kind: SecretKind,
    detector: String,
    surface: crate::model::Surface,
    span: Span,
    value: &'a str,
    key: Option<String>,
    program: Option<String>,
    conf: Confidence,
    base: Severity,
    remediation: Option<crate::model::Remediation>,
    notes: Vec<String>,
    loc: crate::model::LocationRef,
}

fn build(ctx: &Context<'_>, b: &Build<'_>) -> Finding {
    let exposure = b.surface.exposure();
    let sev = adjust_severity(b.base, exposure, &b.loc);
    let mut notes = b.notes.clone();
    if exposure == crate::model::Exposure::WorldReadable
        && !matches!(b.kind, SecretKind::AccessKeyId)
    {
        notes.push("readable by every local user while it exists".into());
    }
    if b.loc.world_readable() && b.loc.file.is_some() {
        notes.push("the containing file is world-readable".into());
    }
    if b.span.is_empty() {
        notes.push("value could not be delimited in the source".into());
    }
    Finding {
        severity: sev,
        confidence: b.conf,
        kind: b.kind,
        provider: b.program.clone(),
        detector: b.detector.clone(),
        location: b.loc.clone(),
        process: ctx.process.clone(),
        program: b.program.clone(),
        key: b.key.clone(),
        span: b.span,
        preview: if b.value.is_empty() { String::new() } else { preview(b.value) },
        fingerprint: if b.value.is_empty() {
            String::new()
        } else {
            crate::model::fingerprint(b.value, ctx.salt)
        },
        value_len: b.value.len(),
        context: String::new(),
        remediation: b.remediation.clone(),
        notes,
        suppressed: false,
    }
}

/// After all detectors ran on one line: drop spans nested inside a stronger
/// finding, and compute the redacted context line.
fn finalize(mut found: Vec<Finding>, raw: &str) -> Vec<Finding> {
    found.retain(|f| !f.span.is_empty() && f.span.end <= raw.len());
    found.sort_by(|a, b| {
        score(b)
            .cmp(&score(a))
            .then(b.span.len().cmp(&a.span.len()))
            .then(a.span.start.cmp(&b.span.start))
    });
    let mut kept: Vec<Finding> = Vec::new();
    for f in found {
        // Drop a finding whose span lies inside one already kept with at least
        // as strong a signal: two detectors seeing the same bytes is one fact.
        let shadowed = kept.iter().any(|k| {
            k.span.contains(f.span) && (k.span.len() >= f.span.len() || score(k) >= score(&f))
        });
        if !shadowed {
            kept.push(f);
        }
    }
    kept.sort_by_key(|f| f.span.start);
    let spans: Vec<Span> = kept.iter().map(|f| f.span).collect();
    let context = redact_spans(raw, &spans);
    for f in kept.iter_mut() {
        f.context = context.clone();
        if f.context.len() > 512 {
            f.context = format!("{}...", &f.context[..512]);
        }
    }
    kept
}

fn score(f: &Finding) -> u32 {
    (f.confidence as u32) * 10 + (f.severity as u32)
}

fn remediation_from(
    m: &'static knowledge::Migration,
    spec: &'static ToolSpec,
    kind: SecretKind,
    surface: crate::model::Surface,
) -> crate::model::Remediation {
    let path = match kind {
        SecretKind::Password | SecretKind::Passphrase => "/etc/credops/db.pass",
        SecretKind::Token | SecretKind::SessionToken => "/etc/credops/api.token",
        SecretKind::ApiKey => "/etc/credops/api.key",
        SecretKind::SecretAccessKey => "/etc/credops/aws.secret",
        _ => "/etc/credops/credential",
    };
    let mut action = format!(
        "{}: read the credential from {} instead of argv",
        spec.name,
        m.channel.label()
    );
    if surface.is_runtime() {
        action.push_str(" (found on a live or logged command line)");
    }
    let _ = kind;
    crate::model::Remediation {
        channel: m.channel,
        action,
        snippet: m.snippet.replace("{PATH}", path),
        caveats: m.caveats.iter().map(|s| s.to_string()).collect(),
        residual: m.residual.to_string(),
    }
}

fn generic_remediation(
    kind: SecretKind,
    channel: Channel,
    program: Option<&str>,
) -> crate::model::Remediation {
    let path = match kind {
        SecretKind::ApiKey => "/etc/credops/api.key",
        SecretKind::Token => "/etc/credops/api.token",
        _ => "/etc/credops/db.pass",
    };
    crate::model::Remediation {
        channel,
        action: format!(
            "{}: move the value out of argv",
            program.unwrap_or("the program")
        ),
        snippet: format!("read the value from {path} (mode 0600) or from stdin"),
        caveats: vec![
            "check that the tool supports a file or stdin form before editing the script".into(),
            "if the tool has no file, stdin or env form, inject the value at exec time with `credops run` and mount /proc with hidepid=2".into(),
        ],
        residual: "credential in a 0600 file or read from stdin".into(),
    }
}

/// The set of value patterns that are credentials regardless of key name.
struct ValuePattern {
    id: &'static str,
    kind: SecretKind,
    provider: Option<&'static str>,
    re: Regex,
    /// Capture group holding the secret; 0 means the whole match.
    secret_group: usize,
}

fn patterns() -> &'static Vec<ValuePattern> {
    static PATTERNS: OnceLock<Vec<ValuePattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let defs: &[(&str, SecretKind, Option<&str>, &str, usize)] = &[
            ("aws-access-key-id", SecretKind::AccessKeyId, Some("aws"),
             r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}\b", 0),
            ("github-token", SecretKind::Token, Some("github"),
             r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,})\b", 0),
            ("gitlab-token", SecretKind::Token, Some("gitlab"),
             r"\bglpat-[A-Za-z0-9_\-]{20,}\b", 0),
            ("slack-token", SecretKind::Token, Some("slack"),
             r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b", 0),
            ("stripe-key", SecretKind::ApiKey, Some("stripe"),
             r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b", 0),
            ("google-api-key", SecretKind::ApiKey, Some("google"),
             r"\bAIza[0-9A-Za-z_\-]{35}\b", 0),
            ("npm-token", SecretKind::Token, Some("npm"),
             r"\bnpm_[A-Za-z0-9]{36}\b", 0),
            ("sendgrid-key", SecretKind::ApiKey, Some("sendgrid"),
             r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b", 0),
            ("jwt", SecretKind::Token, None,
             r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b", 0),
            ("private-key-block", SecretKind::PrivateKey, None,
             r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----", 0),
            ("url-userinfo", SecretKind::Password, None,
             r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@]+:([^/\s@]+)@", 1),
        ];
        defs.iter()
            .map(|(id, kind, provider, re, group)| ValuePattern {
                id,
                kind: *kind,
                provider: *provider,
                re: Regex::new(re).expect("static pattern"),
                secret_group: *group,
            })
            .collect()
    })
}

fn scan_value_patterns(
    raw: &str,
    surface: crate::model::Surface,
    ctx: &Context<'_>,
    out: &mut Vec<Finding>,
) -> Vec<Finding> {
    let mut local = Vec::new();
    for p in patterns() {
        for caps in p.re.captures_iter(raw) {
            let m = caps.get(p.secret_group).or_else(|| caps.get(0));
            let Some(m) = m else { continue };
            let value = m.as_str();
            if classify_value(value, false) != ValueClass::Literal {
                continue;
            }
            let mut l = ctx.location.clone();
            l.surface = surface;
            let mut f = build(
                ctx,
                &Build {
                    kind: p.kind,
                    detector: format!("pattern:{}", p.id),
                    surface,
                    span: Span::new(m.start(), m.end()),
                    value,
                    key: None,
                    program: p.provider.map(|s| s.to_string()),
                    conf: Confidence::High,
                    base: base_severity(p.kind),
                    remediation: Some(generic_remediation(
                        p.kind,
                        Channel::ProtectedFile,
                        p.provider,
                    )),
                    notes: vec![format!("matched the {} credential format", p.id)],
                    loc: l,
                },
            );
            if matches!(p.kind, SecretKind::AccessKeyId) {
                // An access key id alone identifies the account but is not the
                // secret; the matching secret key is what must be rotated.
                f.severity = min_sev(f.severity, Severity::Medium);
                f.notes.push(
                    "an access key id is not a secret by itself; treat the paired secret key as compromised if it was present too"
                        .into(),
                );
            }
            local.push(f);
        }
    }
    out.extend(local.iter().cloned());
    local
}

// ---------------------------------------------------------------------------
// Value classification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueClass {
    Literal,
    Reference,
    Placeholder,
    Empty,
}

pub fn classify_value(value: &str, token_had_substitution: bool) -> ValueClass {
    // Values reconstructed from `/proc` argv or audit records can still carry
    // the shell quotes the wrapper put around them; look through one layer so
    // `"$DB_PASS"` is a reference and `"literal"` is a literal.
    let v = value.trim();
    let v = strip_wrapping_quotes(v);
    if v.is_empty() {
        return ValueClass::Empty;
    }
    // A value that starts with a reference sigil can never be a literal secret
    // in a static file; in argv it would be the *literal* text after expansion,
    // which `emit_value` handles by downgrading confidence instead.
    if v.starts_with('$') || v.starts_with('`') || (token_had_substitution && v.contains("$(")) {
        return ValueClass::Reference;
    }
    let lower = v.to_ascii_lowercase();
    // Protected-input idioms that are named explicitly.
    for prefix in ["file:", "fd:", "env:", "cmd:", "keyring:", "@", "pass:"] {
        if lower.starts_with(prefix) {
            // `pass:` is the *leaking* openssl spelling; everything else is a reference.
            if prefix == "pass:" {
                return ValueClass::Literal;
            }
            return ValueClass::Reference;
        }
    }
    if v.starts_with('-')
        && (v[1..].starts_with('/') || v.len() == 1)
        && v != "-"
        && v.len() <= 2
    {
        return ValueClass::Reference; // `-` means stdin
    }
    if v == "-" {
        return ValueClass::Reference;
    }
    if v.contains("/run/secrets/") || v.contains("/run/credentials/") || v.contains("/dev/fd/") {
        return ValueClass::Reference;
    }
    if is_placeholder(&lower) {
        return ValueClass::Placeholder;
    }
    if v.starts_with('/') || v.starts_with("./") || v.starts_with("~/") {
        // Paths are references to credentials, not credentials.
        return ValueClass::Reference;
    }
    ValueClass::Literal
}

/// Remove one balanced pair of matching quotes, if present.
fn strip_wrapping_quotes(v: &str) -> &str {
    let b = v.as_bytes();
    if b.len() >= 2 {
        let (f, l) = (b[0], b[b.len() - 1]);
        if (f == b'"' && l == b'"') || (f == b'\'' && l == b'\'') {
            let inner = &v[1..v.len() - 1];
            // Do not strip if the quotes do not actually enclose the value.
            if !inner.contains(f as char) {
                return inner;
            }
        }
    }
    v
}

fn is_placeholder(v: &str) -> bool {
    const EXACT: &[&str] = &[
        "changeme", "change_me", "change-me", "password", "passwd", "secret", "xxx", "xxxx",
        "xxxxx", "****", "******", "redacted", "none", "null", "nil", "todo", "fixme",
        "placeholder", "example", "dummy", "test", "your_password", "your-password",
        "yourpassword", "insert_password_here", "changethis", "changeme123",
        "password123", "p@ssw0rd", "foo", "bar", "baz", "abc", "abc123",
        "true", "false", "yes", "no", "1", "0", "on", "off",
    ];
    if EXACT.contains(&v) {
        return true;
    }
    if v.starts_with('<') && v.ends_with('>') {
        return true;
    }
    if v.starts_with("{") && v.ends_with('}') {
        return true;
    }
    if v.starts_with('%') && v.ends_with('%') {
        return true;
    }
    if v.starts_with("${") || (v.starts_with('%') && v.len() > 1) {
        return true;
    }
    // Masked values in logs: `****`, `********`, `xxxxxxx`, `[REDACTED]`.
    let mut chars = v.chars();
    if let Some(first) = chars.next() {
        if matches!(first, '*' | 'x' | 'X' | '.' | '?') && chars.all(|c| c == first) {
            return true;
        }
    }
    if v.starts_with('[') && v.ends_with(']') {
        return true;
    }
    if v.starts_with("$(") || v.starts_with("${") {
        return true;
    }
    // `YOUR_API_KEY_HERE`, `YOUR_PASSWORD`, `MY_TOKEN`, `REPLACE_ME`.
    let upper_placeholder = v.starts_with("your_")
        || v.starts_with("your-")
        || v.starts_with("my_")
        || v.ends_with("_here")
        || v.ends_with("-here")
        || v.contains("replace_me")
        || v.contains("insert_")
        || v.contains("placeholder");
    if upper_placeholder {
        return true;
    }
    false
}

fn looks_entropic(v: &str) -> bool {
    let v = v.trim();
    if v.len() < 8 {
        return false;
    }
    let has_lower = v.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = v.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = v.chars().any(|c| c.is_ascii_digit());
    let has_symbol = v.chars().any(|c| !c.is_ascii_alphanumeric());
    let classes = [has_lower, has_upper, has_digit, has_symbol]
        .iter()
        .filter(|b| **b)
        .count();
    let entropy = shannon(v);
    classes >= 2 && entropy >= 2.5
}

fn shannon(s: &str) -> f64 {
    let mut counts = [0usize; 256];
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / n;
        h -= p * p.log2();
    }
    h
}

fn min_len_for(kind: SecretKind, conf: Confidence) -> usize {
    match (kind, conf) {
        (SecretKind::AccessKeyId, _) => 16,
        (SecretKind::Password, Confidence::Low) => 8,
        (_, Confidence::Low) => 12,
        (SecretKind::Password, _) => 3,
        _ => 6,
    }
}

fn kind_from_key(key: &str) -> SecretKind {
    let l = key.to_ascii_lowercase();
    if l.contains("passw") || l.contains("passwd") || l.contains("pwd") || l.contains("passphrase")
    {
        SecretKind::Password
    } else if l.contains("private") && l.contains("key") {
        SecretKind::PrivateKey
    } else if l.contains("access_key_id") || l.ends_with("keyid") || l.ends_with("key_id") {
        SecretKind::AccessKeyId
    } else if l.contains("secret_access") || l.contains("secret_key") || l.contains("secretkey") {
        SecretKind::SecretAccessKey
    } else if l.contains("token") {
        if l.contains("session") {
            SecretKind::SessionToken
        } else {
            SecretKind::Token
        }
    } else if l.contains("api") && (l.contains("key") || l.contains("token")) {
        SecretKind::ApiKey
    } else if l.contains("conn") && (l.contains("str") || l.contains("string")) {
        SecretKind::ConnectionString
    } else {
        // Includes a bare `secret`. Without a more specific word we cannot
        // tell which kind it is, and guessing would mislabel the rotation.
        SecretKind::OpaqueCredential
    }
}

fn base_severity(kind: SecretKind) -> Severity {
    match kind {
        SecretKind::PrivateKey => Severity::Critical,
        SecretKind::SecretAccessKey => Severity::Critical,
        SecretKind::Password | SecretKind::Passphrase => Severity::High,
        SecretKind::ApiKey | SecretKind::Token | SecretKind::SessionToken => Severity::High,
        SecretKind::ConnectionString => Severity::High,
        SecretKind::AccessKeyId => Severity::Medium,
        SecretKind::OpaqueCredential => Severity::Medium,
    }
}

fn adjust_severity(
    base: Severity,
    exposure: crate::model::Exposure,
    loc: &crate::model::LocationRef,
) -> Severity {
    use crate::model::Exposure::*;
    // An audit record is a durable copy of a cmdline that was world-readable
    // at exec time: the harm is the original exposure, so keep the severity.
    if loc.surface == crate::model::Surface::AuditLog {
        return base;
    }
    match exposure {
        WorldReadable => base,
        OwnerAndRoot | RootOnly => down(base),
        FilePermissions => {
            if loc.world_readable() {
                base
            } else {
                down(base)
            }
        }
    }
}

fn down(s: Severity) -> Severity {
    match s {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low => Severity::Info,
        Severity::Info => Severity::Info,
    }
}

fn min_sev(a: Severity, b: Severity) -> Severity {
    if a < b {
        a
    } else {
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{LocationRef, Surface};

    fn ctx() -> Context<'static> {
        Context::new(LocationRef::file(Surface::ScriptFile, "/tmp/x.sh", 1, Some(0o644)))
    }

    fn scan(raw: &str) -> Vec<Finding> {
        scan_line(raw, Surface::ScriptFile, &ctx())
    }

    fn values(fs: &[Finding]) -> Vec<String> {
        fs.iter()
            .filter(|f| !f.suppressed && f.severity >= Severity::Low)
            .map(|f| f.preview.clone())
            .collect()
    }

    #[test]
    fn mysql_attached_password_found() {
        let fs = scan("mysql -u app -pHunter2Secret db");
        assert_eq!(fs.len(), 1, "{fs:#?}");
        assert_eq!(fs[0].kind, SecretKind::Password);
        assert_eq!(fs[0].detector, "tool:mysql:-p");
        assert_eq!(fs[0].confidence, Confidence::Certain);
        assert_eq!(fs[0].context, "mysql -u app -p*** db");
    }

    #[test]
    fn mysql_bare_dash_p_is_prompt_not_finding() {
        let fs = scan("mysql -u app -p mydb");
        assert!(fs.iter().all(|f| f.severity <= Severity::Info), "{fs:#?}");
        assert!(fs.iter().any(|f| f.notes.iter().any(|n| n.contains("prompts"))));
    }

    #[test]
    fn mysql_long_option_is_not_mistaken_for_dash_p() {
        // `-port=3306` must not be read as `-p ort=3306`.
        let fs = scan("mysql -port=3306 -h db -u app");
        assert!(fs.is_empty(), "{fs:#?}");
    }

    #[test]
    fn mysql_variable_reference_is_not_a_leak() {
        let fs = scan("mysql -p$DB_PASS -u app");
        assert!(fs.is_empty(), "{fs:#?}");
    }

    #[test]
    fn expansion_after_shell_is_flagged_in_argv() {
        let loc = LocationRef::process(42);
        let mut c = Context::new(loc);
        c.process = Some(crate::model::ProcessRef::default());
        let fs = scan_line("mysql -p$DB_PASS", Surface::ProcCmdline, &c);
        // In argv the shell expanded `$DB_PASS`, so the text is the literal.
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].severity, Severity::High);
    }

    #[test]
    fn redis_cli_flag_and_recommended_env() {
        let fs = scan("redis-cli -h 127.0.0.1 -a 'S3cretValue!' ping");
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].detector, "tool:redis-cli:-a");

        let mut c = ctx();
        c.location = LocationRef::process(7);
        c.location.surface = Surface::ProcEnv;
        let env = scan_env("REDISCLI_AUTH", "S3cretValue!", &c);
        assert_eq!(env.len(), 1);
        assert_eq!(env[0].severity, Severity::Info);
        assert!(env[0].notes.iter().any(|n| n.contains("protected channel")));
    }

    #[test]
    fn curl_userinfo_and_url() {
        let fs = scan("curl -u app:Hunter2Pass https://api.example.com");
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].detector, "tool:curl:-u");
        assert_eq!(fs[0].context, "curl -u app:*** https://api.example.com");

        let fs = scan("git clone https://oauth2:ghp_abcdefghijklmnopqrstuvwxyz0123456789@github.com/o/r.git");
        assert!(!fs.is_empty());
        let detectors: Vec<_> = fs.iter().map(|f| f.detector.as_str()).collect();
        assert!(detectors.iter().any(|d| d.contains("url-userinfo") || d.contains("github")));
    }

    #[test]
    fn curl_authorization_header() {
        let fs = scan(r#"curl -H "Authorization: Bearer abcdef0123456789" https://x"#);
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].kind, SecretKind::Token);
        assert!(!fs[0].context.contains("abcdef0123456789"));
    }

    #[test]
    fn protected_file_forms_are_silent() {
        for line in [
            "mysql --defaults-extra-file=/etc/creds.cnf -u app db",
            "mysql --password-file=/run/secrets/db -u app",
            "psql 'postgresql://app@db/mydb' -w",
            "docker login --password-stdin registry",
            "openssl req -pass file:/run/secrets/x",
            "curl -K /etc/curl.cfg https://x",
            "sshpass -f /run/secrets/pw ssh host",
        ] {
            let fs = scan(line);
            assert!(
                fs.iter().all(|f| f.severity <= Severity::Info),
                "{line} -> {fs:#?}"
            );
        }
    }

    #[test]
    fn generic_password_option_detected() {
        let fs = scan("./deploy.sh --db-password=Sup3rS3cretValue --host db");
        assert_eq!(fs.len(), 1, "{fs:#?}");
        assert_eq!(fs[0].detector, "cmdline:option");
        assert_eq!(fs[0].kind, SecretKind::Password);
        assert_eq!(fs[0].severity, Severity::High);
    }

    #[test]
    fn generic_env_assignment_detected() {
        let fs = scan("DB_PASSWORD=Sup3rS3cretValue ./migrate.sh");
        assert_eq!(fs.len(), 1, "{fs:#?}");
        assert_eq!(fs[0].detector, "cmdline:assignment");
        assert_eq!(fs[0].key.as_deref(), Some("DB_PASSWORD"));
    }

    #[test]
    fn file_suffix_keys_are_references() {
        for line in [
            "./run.sh --password-file=/etc/p --token-path /tmp/t",
            "DATABASE_PASSWORD_FILE=/run/secrets/db ./run.sh",
        ] {
            let fs = scan(line);
            assert!(fs.is_empty(), "{line} -> {fs:#?}");
        }
    }

    #[test]
    fn placeholders_not_reported() {
        for line in [
            "mysql -pchangeme",
            "mysql -pxxxxxx",
            "mysql -p<password>",
            "./x --api-key=YOUR_API_KEY_HERE",
        ] {
            let fs = scan(line);
            assert!(
                fs.iter().all(|f| f.severity <= Severity::Info),
                "{line} -> {fs:#?}"
            );
        }
    }

    #[test]
    fn known_value_patterns_fire_without_a_key() {
        let fs = scan("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE aws s3 ls");
        assert!(fs.iter().any(|f| f.detector == "pattern:aws-access-key-id"));
        // The id alone is downgraded.
        let f = fs.iter().find(|f| f.detector == "pattern:aws-access-key-id").unwrap();
        assert!(f.severity <= Severity::Medium);

        let fs = scan("echo ghp_0123456789abcdefghijklmnopqrstuvwxyz");
        assert!(fs.iter().any(|f| f.detector == "pattern:github-token"));
    }

    #[test]
    fn env_scan_strong_and_weak() {
        let mut c = Context::new(LocationRef::process(1));
        c.location.surface = Surface::ProcEnv;

        let fs = scan_env("DATABASE_PASSWORD", "Sup3rS3cret!", &c);
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].kind, SecretKind::Password);
        assert_eq!(fs[0].severity, Severity::Medium); // env is owner/root readable

        let fs = scan_env("DB_PASSWORD", "$(cat /run/secrets/x)", &c);
        assert!(fs.is_empty());

        let fs = scan_env("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", &c);
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].kind, SecretKind::SecretAccessKey);
    }

    #[test]
    fn severity_scales_with_file_permissions() {
        let world = scan_line(
            "mysql -pSup3rS3cret db",
            Surface::ScriptFile,
            &Context::new(LocationRef::file(Surface::ScriptFile, "/tmp/a.sh", 1, Some(0o644))),
        );
        let private = scan_line(
            "mysql -pSup3rS3cret db",
            Surface::ScriptFile,
            &Context::new(LocationRef::file(Surface::ScriptFile, "/root/a.sh", 1, Some(0o600))),
        );
        assert!(world[0].severity > private[0].severity);
    }

    #[test]
    fn overlapping_findings_are_deduped() {
        // Both the tool rule and the generic option rule can see this; only the
        // higher-confidence, longer one should survive.
        let fs = scan("mysql --password=Sup3rS3cret db");
        assert_eq!(fs.len(), 1, "{fs:#?}");
        assert_eq!(fs[0].detector, "tool:mysql:--password");
    }

    #[test]
    fn context_redacts_every_value_on_the_line() {
        let fs = scan("mysql -pHunter2Pass && redis-cli -a OtherSecret9");
        assert_eq!(fs.len(), 2);
        assert!(!fs[0].context.contains("Hunter2Pass"));
        assert!(!fs[0].context.contains("OtherSecret9"));
        assert!(fs[0].context.contains("***"));
        assert_eq!(fs[0].context, fs[1].context);
    }

    #[test]
    fn fingerprints_correlate_but_do_not_reveal() {
        let fs1 = scan("mysql -pHunter2Pass db");
        let fs2 = scan("mysql --password=Hunter2Pass db");
        assert_eq!(fs1[0].fingerprint, fs2[0].fingerprint);
        assert!(!fs1[0].fingerprint.contains("Hunter2"));
    }

    #[test]
    fn sudo_and_timeout_wrappers_still_detect() {
        let fs = scan("sudo -u backup mysqldump -pSup3rS3cret db");
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].detector, "tool:mysqldump:-p");

        let fs = scan("timeout 30 redis-cli -a OtherSecret9 ping");
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].detector, "tool:redis-cli:-a");
    }

    #[test]
    fn smb_percent_and_lftp_comma() {
        let fs = scan("smbclient -U 'app%Sup3rS3cret' //server/share");
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].kind, SecretKind::Password);
        assert!(!fs[0].context.contains("Sup3rS3cret"));

        let fs = scan("lftp -u app,Sup3rS3cret ftp://host");
        assert_eq!(fs.len(), 1);
    }

    #[test]
    fn openssl_pass_forms() {
        let fs = scan("openssl rsa -pass pass:Sup3rS3cret -in k.pem");
        assert_eq!(fs.len(), 1);
        assert!(!fs[0].context.contains("Sup3rS3cret"));

        let fs = scan("openssl rsa -pass stdin -in k.pem");
        assert!(fs.is_empty(), "{fs:#?}");
        let fs = scan("openssl rsa -pass file:/run/secrets/k -in k.pem");
        assert!(fs.is_empty(), "{fs:#?}");
    }

    #[test]
    fn htpasswd_last_positional() {
        let fs = scan("htpasswd -b /etc/nginx/.htpasswd app Sup3rS3cret");
        assert_eq!(fs.len(), 1);
        let fs = scan("htpasswd -c /etc/nginx/.htpasswd app");
        assert!(fs.is_empty(), "{fs:#?}");
    }

    #[test]
    fn ansible_extra_vars() {
        let fs = scan("ansible-playbook site.yml --extra-vars 'db_password=Sup3rS3cret api_key=OtherSecret9'");
        assert_eq!(fs.len(), 2, "{fs:#?}");
        assert!(fs.iter().all(|f| !f.context.contains("Sup3rS3cret")));
        let fs = scan("ansible-playbook site.yml --extra-vars @vault.yml");
        assert!(fs.is_empty(), "{fs:#?}");
    }

    #[test]
    fn weak_key_requires_entropy() {
        let fs = scan("./tool --key=notsecret value");
        assert!(fs.iter().all(|f| f.severity <= Severity::Info), "{fs:#?}");
        let fs = scan("./tool --key=Zx9Qw3Er7Ty5Ui2Op4 value");
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].confidence, Confidence::Low);
    }

    #[test]
    fn password_flag_does_not_eat_the_next_option() {
        let fs = scan("mysql --password --host db");
        assert!(fs.is_empty(), "{fs:#?}");
    }

    #[test]
    fn unicode_and_quotes_redact_correctly() {
        let fs = scan("mysql -p'口令密码123' db");
        assert_eq!(fs.len(), 1);
        // The mask replaces the value; the shell quotes around it are kept, so
        // the redacted line is still valid shell and shows the value was quoted.
        assert_eq!(fs[0].context, "mysql -p'***' db");
        assert_eq!(fs[0].value_len, "口令密码123".len());
    }

    #[test]
    fn connection_string_counts_as_reference_or_secret() {
        let fs = scan("./app --dsn postgres://app:Sup3rS3cret@db:5432/x");
        assert!(!fs.is_empty(), "{fs:#?}");
        assert!(fs.iter().all(|f| !f.context.contains("Sup3rS3cret")));
    }

    #[test]
    fn no_finding_for_unrelated_commands() {
        for line in [
            "ls -la /tmp",
            "systemctl restart nginx",
            "python3 main.py --verbose",
            "grep -r password /etc",
            "ssh -i /home/app/.ssh/id_ed25519 host",
        ] {
            assert!(scan(line).is_empty(), "{line}");
        }
    }

    #[test]
    fn values_helper_sanity() {
        let fs = scan("mysql -pHunter2Secret db");
        assert_eq!(values(&fs).len(), 1);
    }
}
