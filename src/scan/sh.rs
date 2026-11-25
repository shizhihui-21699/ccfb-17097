//! Shell-command lexing for argv-level analysis.
//!
//! Command lines are not `split_whitespace()`. We need to know, for every
//! character we report, exactly which raw byte it came from (so redaction is
//! offset-correct), whether it was quoted, and whether it came from a command
//! substitution (`$(...)`, backticks) or a variable expansion (`$FOO`,
//! `${FOO}`), because those mean the text is a *reference*, not a secret.

use crate::model::Span;

/// A single word (argv element, or `NAME=value` assignment prefix).
#[derive(Debug, Clone)]
pub struct Token {
    /// Byte span of the whole word in the source line.
    pub span: Span,
    /// Dequoted text of the word.
    pub text: String,
    /// `map[i]` is the raw byte index in the source line of `text`'s byte `i`.
    /// Always `map.len() == text.len() + 1` (last entry = raw end of the word).
    pub map: Vec<usize>,
    /// The word contained quotes of some kind.
    pub quoted: bool,
    /// The word contains a command substitution or variable expansion; its
    /// text is not a pure literal.
    pub substitution: bool,
    /// The word is an assignment prefix (`NAME=value`) rather than an argument.
    pub is_assignment: bool,
    /// The word is pure redirection syntax (`>`, `2>&1`, `<`, ...).
    pub is_redirect: bool,
}

impl Token {
    /// Raw source slice covering this whole word.
    pub fn raw<'a>(&self, src: &'a str) -> &'a str {
        &src[self.span.start..self.span.end]
    }

    /// Map a span in `text` coordinates back to source coordinates.
    pub fn to_raw(&self, s: Span) -> Span {
        let start = self.map.get(s.start).copied().unwrap_or(self.span.end);
        let end = self.map.get(s.end).copied().unwrap_or(self.span.end);
        Span::new(start.min(end), start.max(end))
    }

    /// Sub-slice of the raw word corresponding to a `text` span.
    pub fn raw_of<'a>(&self, src: &'a str, s: Span) -> &'a str {
        let r = self.to_raw(s);
        &src[r.start..r.end]
    }
}

/// One simple command: the words between separators (`;`, `&&`, `|`, ...).
#[derive(Debug, Clone, Default)]
pub struct SimpleCommand {
    pub tokens: Vec<Token>,
    /// Index in `tokens` of the command word, if any (after assignment
    /// prefixes and redirections).
    pub argv_start: Option<usize>,
    /// Source span of the whole simple command.
    pub span: Span,
}

impl SimpleCommand {
    /// Program name as written (basename not applied).
    pub fn program(&self) -> Option<&str> {
        self.argv_start.map(|i| self.tokens[i].text.as_str())
    }

    /// Program name lowercased, path stripped, with `sudo`-like wrappers
    /// peeled so `sudo -u x mysql -pfoo` is still analysed as `mysql`.
    pub fn effective_program(&self) -> Option<(String, usize)> {
        let mut i = self.argv_start?;
        loop {
            let prog = basename(&self.tokens[i].text).to_ascii_lowercase();
            if !is_wrapper(&prog) {
                return Some((prog, i));
            }
            // Skip the wrapper's own options to find the inner command.
            let mut j = i + 1;
            // `timeout 30 cmd`, `timeout 1h cmd`: the duration is positional.
            if matches!(prog.as_str(), "timeout" | "time") {
                while j < self.tokens.len() && is_duration(&self.tokens[j].text) {
                    j += 1;
                }
            }
            while j < self.tokens.len() {
                let t = &self.tokens[j].text;
                if t == "--" {
                    j += 1;
                    break;
                }
                if t.starts_with('-') {
                    // Options that consume the following word.
                    let takes_arg = matches!(
                        t.as_str(),
                        "-u" | "-g" | "-n" | "-p" | "-C" | "-s" | "-k"
                            | "--user" | "--group" | "--uid" | "--gid"
                    );
                    j += if takes_arg { 2 } else { 1 };
                    continue;
                }
                // `env NAME=value cmd` assignment forms.
                if prog == "env" && assignment_split(t).is_some() {
                    j += 1;
                    continue;
                }
                break;
            }
            if j >= self.tokens.len() {
                return Some((prog, i));
            }
            i = j;
        }
    }
}

fn is_duration(s: &str) -> bool {
    !s.is_empty()
        && s.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false)
        && s.chars().all(|c| c.is_ascii_digit() || matches!(c, '.' | 's' | 'm' | 'h' | 'd'))
}

fn is_wrapper(p: &str) -> bool {
    matches!(
        p,
        "sudo" | "doas" | "env" | "nohup" | "nice" | "ionice" | "timeout" | "stdbuf"
            | "exec" | "command" | "time" | "setsid" | "unbuffer" | "xargs" | "builtin"
    )
}

pub fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

fn push_ch(ch: char, raw_idx: usize, text: &mut String, map: &mut Vec<usize>) {
    let before = text.len();
    text.push(ch);
    for _ in before..text.len() {
        map.push(raw_idx);
    }
}

fn copy_run(src: &str, start: usize, end: usize, text: &mut String, map: &mut Vec<usize>) {
    if start >= end {
        return;
    }
    for (off, ch) in src[start..end].char_indices() {
        push_ch(ch, start + off, text, map);
    }
}

/// Lex a full line into simple commands.
pub fn lex_line(src: &str) -> Vec<SimpleCommand> {
    let mut out = Vec::new();
    let mut cur = SimpleCommand::default();
    let bytes = src.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b' ' | b'\t' | b'\r' => i += 1,
            b'\n' | b';' | b'&' | b'|' => {
                flush(&mut cur, &mut out, i);
                i += 1;
                while i < bytes.len() && matches!(bytes[i], b'&' | b'|') {
                    i += 1;
                }
            }
            // A `#` is a comment only at the start of a word.
            b'#' => break,
            _ => {
                let (tok, next) = lex_word(src, i);
                cur.tokens.push(tok);
                i = next;
            }
        }
    }
    flush(&mut cur, &mut out, bytes.len());
    out
}

fn flush(cur: &mut SimpleCommand, out: &mut Vec<SimpleCommand>, end: usize) {
    if cur.tokens.is_empty() {
        return;
    }
    let start = cur.tokens[0].span.start;
    cur.span = Span::new(start, end);
    finalize_argv(cur);
    out.push(std::mem::take(cur));
}

/// Decide which token is the command word: skip assignment prefixes and
/// redirection syntax.
fn finalize_argv(cmd: &mut SimpleCommand) {
    let mut idx = 0usize;
    while idx < cmd.tokens.len() {
        if cmd.tokens[idx].is_redirect {
            idx += 1;
            continue;
        }
        if assignment_split(&cmd.tokens[idx].text).is_some() {
            cmd.tokens[idx].is_assignment = true;
            idx += 1;
            continue;
        }
        cmd.argv_start = Some(idx);
        return;
    }
}

/// If `text` starts with a valid shell identifier followed by `=`, return the
/// byte index of the `=`.
pub fn assignment_split(text: &str) -> Option<usize> {
    let mut it = text.char_indices();
    match it.next() {
        Some((_, c)) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return None,
    }
    for (i, c) in it {
        if c == '=' {
            return Some(i);
        }
        if !(c == '_' || c.is_ascii_alphanumeric()) {
            return None;
        }
    }
    None
}

fn lex_word(src: &str, start: usize) -> (Token, usize) {
    let bytes = src.as_bytes();
    let mut i = start;
    let mut text = String::new();
    let mut map: Vec<usize> = Vec::new();
    let mut quoted = false;
    let mut substitution = false;
    // Raw offset just past the last character copied into `text`. The final
    // map entry uses this, not `i`, so a closing quote does not extend the
    // value's raw span (and would otherwise corrupt redaction).
    let mut content_end = start;

    // Redirection detection at word start: `>`, `>>`, `<`, `2>`, `&>`.
    let is_redirect = {
        let mut k = start;
        while k < bytes.len() && raw_is_digit(bytes, start, k) && k - start < 2 {
            k += 1;
        }
        k < bytes.len() && (bytes[k] == b'>' || bytes[k] == b'<')
    };

    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b' ' | b'\t' | b'\r' | b'\n' | b';' | b'&' | b'|' => {
                break;
            }
            b'\'' => {
                quoted = true;
                i += 1;
                let seg = i;
                while i < bytes.len() && bytes[i] != b'\'' {
                    i += 1;
                }
                copy_run(src, seg, i, &mut text, &mut map);
                content_end = content_end.max(i);
                i += 1; // closing quote
            }
            b'"' => {
                quoted = true;
                i += 1;
                let mut seg = i;
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'$' && i + 1 < bytes.len()
                        && matches!(bytes[i + 1], b'(' | b'{')
                    {
                        copy_run(src, seg, i, &mut text, &mut map);
                        substitution = true;
                        let n = if bytes[i + 1] == b'(' {
                            i + 1 + scan_balanced(&src[i + 1..], 0, b'(', b')')
                        } else {
                            i + 1 + scan_brace(&src[i + 1..])
                        };
                        copy_run(src, i, n, &mut text, &mut map);
                        content_end = content_end.max(n);
                        i = n;
                        seg = i;
                        continue;
                    }
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        copy_run(src, seg, i, &mut text, &mut map);
                        let n = bytes[i + 1];
                        match n {
                            b'$' | b'`' | b'"' | b'\\' => {
                                if n == b'$' || n == b'`' {
                                    substitution = true;
                                }
                                push_ch(n as char, i + 1, &mut text, &mut map);
                                content_end = content_end.max(i + 2);
                                i += 2;
                            }
                            b'\n' => i += 2,
                            _ => {
                                push_ch('\\', i, &mut text, &mut map);
                                content_end = content_end.max(i + 1);
                                i += 1;
                            }
                        }
                        seg = i;
                        continue;
                    }
                    if bytes[i] == b'$' || bytes[i] == b'`' {
                        substitution = true;
                    }
                    i += 1;
                }
                copy_run(src, seg, i, &mut text, &mut map);
                content_end = content_end.max(i);
                i += 1; // closing quote
            }
            b'\\' => {
                if i + 1 < bytes.len() {
                    let rest = &src[i + 1..];
                    let mut it = rest.char_indices();
                    if let Some((_, ch)) = it.next() {
                        if ch == '\n' {
                            i += 2;
                            continue;
                        }
                        let adv = ch.len_utf8();
                        push_ch(ch, i + 1, &mut text, &mut map);
                        content_end = content_end.max(i + 1 + adv);
                        i += 1 + adv;
                    } else {
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            }
            b'$' => {
                substitution = true;
                let (consumed, sub) = scan_dollar(&src[i..]);
                for (off, ch) in sub.char_indices() {
                    push_ch(ch, i + off, &mut text, &mut map);
                }
                content_end = content_end.max(i + consumed);
                i += consumed;
            }
            b'`' => {
                substitution = true;
                let (consumed, sub) = scan_backtick(&src[i..]);
                for (off, ch) in sub.char_indices() {
                    push_ch(ch, i + off, &mut text, &mut map);
                }
                content_end = content_end.max(i + consumed);
                i += consumed;
            }
            _ => {
                let end = (i + utf8_len(c)).min(bytes.len());
                copy_run(src, i, end, &mut text, &mut map);
                content_end = content_end.max(end);
                i = end;
            }
        }
    }

    map.push(content_end);
    (
        Token {
            span: Span::new(start, i),
            text,
            map,
            quoted,
            substitution,
            is_assignment: false,
            is_redirect,
        },
        i,
    )
}

fn raw_is_digit(bytes: &[u8], start: usize, k: usize) -> bool {
    k >= start && bytes[k].is_ascii_digit()
}

fn utf8_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b >> 5 == 0b110 {
        2
    } else if b >> 4 == 0b1110 {
        3
    } else if b >> 3 == 0b11110 {
        4
    } else {
        1
    }
}

/// Scan a `$`-form: `$NAME`, `${...}`, `$(...)`. Returns bytes consumed and
/// the verbatim slice.
fn scan_dollar(s: &str) -> (usize, String) {
    let b = s.as_bytes();
    if b.len() < 2 {
        return (1, "$".to_string());
    }
    match b[1] {
        b'{' => {
            let mut depth = 1usize;
            let mut i = 2usize;
            while i < b.len() && depth > 0 {
                match b[i] {
                    b'{' => depth += 1,
                    b'}' => depth -= 1,
                    _ => {}
                }
                i += 1;
            }
            (i, s[..i].to_string())
        }
        b'(' => {
            let n = scan_balanced(s, 1, b'(', b')');
            (n, s[..n].to_string())
        }
        _ => {
            let mut i = 1usize;
            while i < b.len() && (b[i] == b'_' || b[i].is_ascii_alphanumeric()) {
                i += 1;
            }
            if i == 1 {
                (1, "$".to_string())
            } else {
                (i, s[..i].to_string())
            }
        }
    }
}

fn scan_backtick(s: &str) -> (usize, String) {
    let b = s.as_bytes();
    let mut i = 1usize;
    while i < b.len() {
        if b[i] == b'\\' {
            i += 2;
            continue;
        }
        if b[i] == b'`' {
            i += 1;
            break;
        }
        i += 1;
    }
    let n = i.min(b.len());
    (n, s[..n].to_string())
}

/// Scan `${...}`, starting at the `{`. Returns bytes consumed including braces.
fn scan_brace(s: &str) -> usize {
    let b = s.as_bytes();
    let mut depth = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        match b[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    b.len()
}

/// Scan a balanced `open`/`close` group starting at the opener.
fn scan_balanced(s: &str, open_idx: usize, open: u8, close: u8) -> usize {
    let b = s.as_bytes();
    let mut depth = 0usize;
    let mut i = open_idx;
    while i < b.len() {
        let c = b[i];
        if c == b'\\' {
            i += 2;
            continue;
        }
        if c == b'\'' {
            i += 1;
            while i < b.len() && b[i] != b'\'' {
                i += 1;
            }
            i += 1;
            continue;
        }
        if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return i + 1;
            }
        }
        i += 1;
    }
    b.len()
}

/// Split a dequoted token like `--password=x` or `password: x` into
/// `(key_text, value_start_index)` and the value slice.
pub fn split_kv(text: &str) -> Option<(&str, usize)> {
    if let Some(eq) = text.find('=') {
        let (k, v) = text.split_at(eq);
        if !k.is_empty() && !k.contains('/') && !v[1..].starts_with('=') {
            return Some((k, eq + 1));
        }
    }
    if let Some(colon) = text.find(':') {
        let (k, v) = text.split_at(colon);
        if !k.is_empty()
            && !k.contains('/')
            && !v.starts_with("://")
            && k.chars().all(|c| c == '_' || c == '-' || c.is_ascii_alphanumeric())
        {
            let after = colon + 1;
            let ws = v[1..].len() - v[1..].trim_start().len();
            return Some((k, after + ws));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_argv() {
        let cmds = lex_line("mysql -u app -pHunter2 db");
        assert_eq!(cmds.len(), 1);
        let c = &cmds[0];
        assert_eq!(c.program(), Some("mysql"));
        let args: Vec<&str> = c.tokens.iter().map(|t| t.text.as_str()).collect();
        assert_eq!(args, vec!["mysql", "-u", "app", "-pHunter2", "db"]);
    }

    #[test]
    fn quoted_password_keeps_raw_offsets() {
        let line = r#"mysql --password="s3cr3t value" db"#;
        let cmds = lex_line(line);
        let tok = cmds[0]
            .tokens
            .iter()
            .find(|t| t.text.starts_with("--password="))
            .unwrap();
        let eq = tok.text.find('=').unwrap();
        let val = Span::new(eq + 1, tok.text.len());
        // The value's raw span excludes the quotes themselves: redaction must
        // not leave `-p\"***\"` behind.
        assert_eq!(tok.raw_of(line, val), "s3cr3t value");
        assert_eq!(tok.text, "--password=s3cr3t value");
    }

    #[test]
    fn separators_split_commands() {
        let cmds = lex_line("a=1 mysql -px; redis-cli -a y && echo done");
        assert_eq!(cmds.len(), 3);
        assert_eq!(cmds[0].program(), Some("mysql"));
        assert_eq!(cmds[1].program(), Some("redis-cli"));
        assert_eq!(cmds[2].program(), Some("echo"));
    }

    #[test]
    fn assignment_prefix_is_flagged() {
        let cmds = lex_line("DB_PASS=hunter2 mysql -u app");
        let c = &cmds[0];
        assert!(c.tokens[0].is_assignment);
        assert_eq!(c.program(), Some("mysql"));
    }

    #[test]
    fn substitution_is_flagged() {
        let cmds = lex_line(r#"mysql -p"$(cat /run/secrets/db)""#);
        let tok = &cmds[0].tokens[1];
        assert!(tok.substitution);
        assert!(tok.text.contains("$("));
    }

    #[test]
    fn variable_reference_flagged() {
        let cmds = lex_line("mysql -p$DB_PASS");
        assert!(cmds[0].tokens[1].substitution);
        let cmds = lex_line("mysql -p${DB_PASS}");
        assert!(cmds[0].tokens[1].substitution);
        assert_eq!(cmds[0].tokens[1].text, "-p${DB_PASS}");
    }

    #[test]
    fn comment_ignored() {
        assert!(lex_line("# mysql -pHunter2").is_empty());
        let cmds = lex_line("mysql -pHunter2 # trailing");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].tokens.len(), 2);
    }

    #[test]
    fn redirect_flagged() {
        let cmds = lex_line("mysql -pX > /tmp/out 2>&1");
        let redir: Vec<_> = cmds[0].tokens.iter().filter(|t| t.is_redirect).collect();
        assert_eq!(redir.len(), 2);
    }

    #[test]
    fn sudo_wrapper_peeled() {
        let cmds = lex_line("sudo -u backup /usr/bin/mysqldump -pX db");
        let (prog, idx) = cmds[0].effective_program().unwrap();
        assert_eq!(prog, "mysqldump");
        assert_eq!(cmds[0].tokens[idx].text, "/usr/bin/mysqldump");
    }

    #[test]
    fn timeout_wrapper_peeled() {
        let cmds = lex_line("timeout 30 curl -u a:b https://x");
        let (prog, _) = cmds[0].effective_program().unwrap();
        assert_eq!(prog, "curl");
    }

    #[test]
    fn split_kv_forms() {
        assert_eq!(split_kv("--password=abc"), Some(("--password", 11)));
        assert_eq!(split_kv("password: abc"), Some(("password", 10)));
        assert_eq!(split_kv("--password"), None);
        assert_eq!(split_kv("https://u:p@h"), None);
    }

    #[test]
    fn backslash_escapes_outside_quotes() {
        let cmds = lex_line(r"mysql -pfoo\ bar db");
        assert_eq!(cmds[0].tokens[1].text, "-pfoo bar");
        assert_eq!(cmds[0].tokens[2].text, "db");
    }

    #[test]
    fn multibyte_values_do_not_panic_and_map_correctly() {
        let line = "mysql -p口令密码123";
        let cmds = lex_line(line);
        let tok = &cmds[0].tokens[1];
        assert_eq!(tok.text, "-p口令密码123");
        assert_eq!(tok.text.len(), tok.map.len() - 1);
        // Every mapped raw offset must be a char boundary.
        for &m in &tok.map {
            assert!(line.is_char_boundary(m), "bad offset {m}");
        }
        let value = Span::new(2, tok.text.len());
        assert_eq!(tok.raw_of(line, value), "口令密码123");
    }

    #[test]
    fn single_quoted_multibyte() {
        let line = "mysql -p'口令'";
        let cmds = lex_line(line);
        assert_eq!(cmds[0].tokens[1].text, "-p口令");
        assert!(cmds[0].tokens[1].quoted);
    }

    #[test]
    fn nested_substitution_balanced() {
        let cmds = lex_line(r#"mysql -p"$(printf '%s' "${X}")""#);
        assert_eq!(cmds[0].tokens.len(), 2);
        assert!(cmds[0].tokens[1].substitution);
    }
}
