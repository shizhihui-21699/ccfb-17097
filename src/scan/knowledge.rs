//! Curated knowledge about how programs accept credentials.
//!
//! Every entry here is a statement about a real CLI. The point of the table is
//! precision: `mysql -p` with no value is a *prompt* and is safe, while
//! `mysql -pX` is a world-readable secret. A generic regex cannot tell those
//! apart, and a scanner that cries wolf on `--password-file` gets turned off.
//!
//! Each tool also carries the migration that is actually available for it,
//! because "stop passing passwords on the command line" is not advice until it
//! says *what to type instead*.

use crate::model::{Channel, SecretKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// Only `--flag value`.
    Separate,
    /// Only `--flag=value`.
    Equals,
    /// Either spelling.
    Both,
}

#[derive(Debug, Clone, Copy)]
pub enum ArgRule {
    /// `-pVALUE`: the value is glued to the option, no space allowed.
    /// `require_value == false` makes a bare `-p` (a prompt) a non-finding.
    Attached {
        prefix: &'static str,
        kind: SecretKind,
        require_value: bool,
    },
    /// A named option that takes the secret as its value.
    Flag {
        flag: &'static str,
        form: Form,
        kind: SecretKind,
    },
    /// `-u user:password` / `--user=user:password`: only the part after the
    /// last `:` is the secret.
    UserInfo {
        flag: &'static str,
        kind: SecretKind,
    },
    /// Any argument that is a URL carrying `user:password@`.
    UrlUserInfo,
    /// `-U user%password` (smbclient, mount.cifs).
    PercentUserPass { flag: &'static str },
    /// `-u user,password` (lftp).
    CommaUserPass { flag: &'static str },
    /// `-pass pass:VALUE` (openssl).
    PassSpec { flag: &'static str },
    /// `-H 'Authorization: Bearer VALUE'` and friends.
    AuthHeader { flag: &'static str },
    /// `--extra-vars 'db_password=VALUE'` (ansible).
    ExtraVars { flag: &'static str },
    /// The last positional argument is the secret, but only when `flag` is
    /// present (`htpasswd -b FILE USER PASSWORD`).
    LastPositional { flag: &'static str },
}

#[derive(Debug, Clone, Copy)]
pub struct EnvRule {
    pub name: &'static str,
    pub kind: SecretKind,
    /// `true` when this variable *is* the recommended protected channel, so
    /// seeing it is good news rather than a finding.
    pub recommended: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct Migration {
    pub channel: Channel,
    /// Shell snippet with `{SECRET}` (the value) and `{PATH}` (a suggested
    /// protected file path) placeholders.
    pub snippet: &'static str,
    pub caveats: &'static [&'static str],
    pub residual: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct ToolSpec {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub provider: Option<&'static str>,
    pub rules: &'static [ArgRule],
    pub env: &'static [EnvRule],
    pub migration: Migration,
}

macro_rules! tool {
    ($name:expr, $aliases:expr, $provider:expr, rules [$($rule:expr),* $(,)?], env [$($env:expr),* $(,)?], $mig:expr) => {
        ToolSpec {
            name: $name,
            aliases: $aliases,
            provider: $provider,
            rules: &[$($rule),*],
            env: &[$($env),*],
            migration: $mig,
        }
    };
}

const MYSQL_MIG: Migration = Migration {
    channel: Channel::ProtectedFile,
    snippet: concat!(
        "# write this once, as the service user, to a mode-0600 file:\n",
        "#   printf '[client]\\npassword=%s\\n' \"{SECRET}\" > {PATH}; chmod 600 {PATH}\n",
        "mysql --defaults-extra-file={PATH} -u app mydb"
    ),
    caveats: &[
        "--defaults-extra-file must be the first option on the command line",
        "mysql refuses a config file that is group- or world-writable",
        "the password now lives on disk; protect the file with fs permissions and backups",
    ],
    residual: "password on disk in a 0600 file owned by the service account",
};

const PG_MIG: Migration = Migration {
    channel: Channel::ProtectedFile,
    snippet: concat!(
        "# write this once, as the service user, to a mode-0600 PGPASSFILE:\n",
        "#   printf '%s\\n' 'db.example.com:5432:mydb:app:{SECRET}' > {PATH}; chmod 600 {PATH}\n",
        "PGPASSFILE={PATH} psql -h db.example.com -U app mydb"
    ),
    caveats: &[
        "libpq refuses a .pgpass that is readable by group or others",
        "PGPASSWORD in the environment still exposes the value to root and to /proc/<pid>/environ of peers of the same uid",
    ],
    residual: "password on disk in a 0600 file owned by the service account",
};

const CURL_MIG: Migration = Migration {
    channel: Channel::ToolConfigFile,
    snippet: concat!(
        "# keep a mode-0600 curl config with the credential:\n",
        "#   printf 'user = \"app:%s\"\\n' \"{SECRET}\" > {PATH}; chmod 600 {PATH}\n",
        "curl -K {PATH} https://api.example.com/"
    ),
    caveats: &[
        "curl also accepts `-K -` to read the config from stdin, which keeps the value out of the filesystem entirely",
        "a config file referenced by -K is not protected from other processes of the same uid, only from other users",
    ],
    residual: "credential in a 0600 file, or on stdin when -K - is used",
};

const REDIS_MIG: Migration = Migration {
    channel: Channel::Env,
    snippet: "REDISCLI_AUTH=\"$(cat {PATH})\" redis-cli -h 127.0.0.1 -p 6379",
    caveats: &[
        "the environment is readable by the owning uid and by root, unlike argv which is readable by every user",
        "redis-cli 7.0 and later also support --askpass, which prompts without storing the value at all",
    ],
    residual: "credential in the process environment of the service account",
};

const SSH_MIG: Migration = Migration {
    channel: Channel::Fd,
    snippet: concat!(
        "# sshpass can read the password from a file descriptor instead of argv:\n",
        "sshpass -d 3 ssh -o PreferredAuthentications=password user@host < {PATH} 3< {PATH}"
    ),
    caveats: &[
        "prefer key-based authentication over any password transport",
        "sshpass -e reads SSHPASS from the environment and is the usual smaller change",
    ],
    residual: "credential read from a 0600 file into a private fd",
};

const DOCKER_MIG: Migration = Migration {
    channel: Channel::Stdin,
    snippet: "cat {PATH} | docker login --username app --password-stdin registry.example.com",
    caveats: &["--password-stdin is the only non-interactive form docker documents as safe"],
    residual: "credential on stdin only; docker stores it in ~/.docker/config.json afterwards",
};

const OPENSSL_MIG: Migration = Migration {
    channel: Channel::Stdin,
    snippet: "openssl ... -pass stdin < {PATH}",
    caveats: &[
        "prefer `-pass file:{PATH}` or `-pass fd:N` when stdin is not free",
        "`-pass pass:...` is exactly the pattern being replaced",
    ],
    residual: "credential on stdin or read from a 0600 file",
};

const AWS_MIG: Migration = Migration {
    channel: Channel::ProtectedFile,
    snippet: concat!(
        "# ~/.aws/credentials, mode 0600:\n",
        "#   [default]\n",
        "#   aws_access_key_id = ...\n",
        "#   aws_secret_access_key = {SECRET}\n",
        "aws s3 ls --profile default"
    ),
    caveats: &[
        "prefer an instance role or SSO over a long-lived secret key",
        "AWS_* environment variables are visible to root and to same-uid processes",
    ],
    residual: "long-lived key on disk in a 0600 file",
};

const GIT_MIG: Migration = Migration {
    channel: Channel::ToolConfigFile,
    snippet: concat!(
        "# use a credential helper or a per-host token file instead of userinfo in the URL:\n",
        "git -c credential.helper='store --file={PATH}' clone https://github.com/org/repo.git\n",
        "# {PATH} holds https://app:{SECRET}@github.com (mode 0600)"
    ),
    caveats: &[
        "the URL with userinfo is also copied into .git/config and into `git remote -v` output",
        "a credential helper keeps the token out of argv, but not out of the helper's own store",
    ],
    residual: "token in a 0600 credential file",
};

const ARGV_LAST_RESORT: Migration = Migration {
    channel: Channel::ArgvOnly,
    snippet: concat!(
        "# This tool accepts the credential only in argv, so it cannot be hidden\n",
        "# from the tool itself. Do two things instead:\n",
        "#   1. stop writing the value into scripts/history: inject it at exec time\n",
        "#      credops run --secret-file {PATH} -- {CMD} -p{SECRET}\n",
        "#   2. make /proc unreadable to other users on this host:\n",
        "#      mount -o remount,hidepid=2 /proc      # or systemd: ProtectProc=invisible"
    ),
    caveats: &[
        "the value remains readable in /proc/<pid>/cmdline for as long as the process runs",
        "hidepid=2 makes cmdline readable only by the owning uid and root, which is the same protection environ already has",
        "run the job as a dedicated service uid so root-only is a narrower set than 'everyone'",
    ],
    residual: "credential in argv, readable by the service uid and root only when hidepid=2 is set",
};

const SMB_MIG: Migration = Migration {
    channel: Channel::ProtectedFile,
    snippet: concat!(
        "# credentials file, mode 0600:\n",
        "#   username=app\n",
        "#   password={SECRET}\n",
        "smbclient -A {PATH} //server/share"
    ),
    caveats: &["the file must not be readable by anyone but its owner"],
    residual: "credential on disk in a 0600 file",
};

const WGET_MIG: Migration = Migration {
    channel: Channel::ToolConfigFile,
    snippet: concat!(
        "# mode-0600 netrc-style credentials file:\n",
        "#   machine example.com login app password {SECRET}\n",
        "wget --netrc-file={PATH} https://example.com/"
    ),
    caveats: &["--netrc-file is only honoured for the host named in the file"],
    residual: "credential on disk in a 0600 file",
};

const KEYTOOL_MIG: Migration = Migration {
    channel: Channel::ProtectedFile,
    snippet: "keytool ... -storepass:file {PATH}",
    caveats: &[
        "-storepass:file requires JDK 18 or later; older JDKs only take the value in argv",
        "on older JDKs the value must be in argv; inject it with `credops run` and set hidepid=2",
    ],
    residual: "credential read from a 0600 file",
};

pub static TOOLS: &[ToolSpec] = &[
    tool!(
        "mysql",
        &["mariadb", "mysqladmin", "mysqlcheck", "mysqlimport"],
        Some("mysql"),
        rules [
            ArgRule::Attached { prefix: "-p", kind: SecretKind::Password, require_value: true },
            ArgRule::Flag { flag: "--password", form: Form::Equals, kind: SecretKind::Password },
        ],
        env [
            EnvRule { name: "MYSQL_PWD", kind: SecretKind::Password, recommended: false },
        ],
        MYSQL_MIG
    ),
    tool!(
        "mysqldump",
        &[],
        Some("mysql"),
        rules [
            ArgRule::Attached { prefix: "-p", kind: SecretKind::Password, require_value: true },
            ArgRule::Flag { flag: "--password", form: Form::Equals, kind: SecretKind::Password },
        ],
        env [
            EnvRule { name: "MYSQL_PWD", kind: SecretKind::Password, recommended: false },
        ],
        MYSQL_MIG
    ),
    tool!(
        "mysqlsh",
        &[],
        Some("mysql"),
        rules [
            ArgRule::Flag { flag: "--password", form: Form::Both, kind: SecretKind::Password },
            ArgRule::UrlUserInfo,
        ],
        env [
            EnvRule { name: "MYSQL_PWD", kind: SecretKind::Password, recommended: false },
        ],
        MYSQL_MIG
    ),
    tool!(
        "psql",
        &["pg_dump", "pg_dumpall", "pg_restore", "vacuumdb", "createdb", "createuser", "dropdb"],
        Some("postgres"),
        rules [ArgRule::UrlUserInfo],
        env [
            EnvRule { name: "PGPASSWORD", kind: SecretKind::Password, recommended: false },
            EnvRule { name: "PGPASSFILE", kind: SecretKind::Password, recommended: true },
        ],
        PG_MIG
    ),
    tool!(
        "redis-cli",
        &[],
        Some("redis"),
        rules [
            ArgRule::Flag { flag: "-a", form: Form::Separate, kind: SecretKind::Password },
            ArgRule::Flag { flag: "--pass", form: Form::Both, kind: SecretKind::Password },
            ArgRule::Flag { flag: "--user", form: Form::Both, kind: SecretKind::Password },
            ArgRule::UrlUserInfo,
        ],
        env [
            EnvRule { name: "REDISCLI_AUTH", kind: SecretKind::Password, recommended: true },
        ],
        REDIS_MIG
    ),
    tool!(
        "mongosh",
        &["mongo"],
        Some("mongo"),
        rules [
            ArgRule::Flag { flag: "-p", form: Form::Separate, kind: SecretKind::Password },
            ArgRule::Flag { flag: "--password", form: Form::Both, kind: SecretKind::Password },
            ArgRule::Flag { flag: "-u", form: Form::Separate, kind: SecretKind::Password },
            ArgRule::UrlUserInfo,
        ],
        env [],
        REDIS_MIG
    ),
    tool!(
        "curl",
        &[],
        None,
        rules [
            ArgRule::UserInfo { flag: "-u", kind: SecretKind::Password },
            ArgRule::UserInfo { flag: "--user", kind: SecretKind::Password },
            ArgRule::UserInfo { flag: "--proxy-user", kind: SecretKind::Password },
            ArgRule::AuthHeader { flag: "-H" },
            ArgRule::AuthHeader { flag: "--header" },
            ArgRule::UrlUserInfo,
        ],
        env [],
        CURL_MIG
    ),
    tool!(
        "wget",
        &[],
        None,
        rules [
            ArgRule::Flag { flag: "--password", form: Form::Both, kind: SecretKind::Password },
            ArgRule::Flag { flag: "--http-password", form: Form::Both, kind: SecretKind::Password },
            ArgRule::Flag { flag: "--ftp-password", form: Form::Both, kind: SecretKind::Password },
            ArgRule::UrlUserInfo,
        ],
        env [],
        WGET_MIG
    ),
    tool!(
        "sshpass",
        &[],
        None,
        rules [
            ArgRule::Attached { prefix: "-p", kind: SecretKind::Password, require_value: true },
            ArgRule::Flag { flag: "-p", form: Form::Separate, kind: SecretKind::Password },
        ],
        env [],
        SSH_MIG
    ),
    tool!(
        "openssl",
        &[],
        None,
        rules [ArgRule::PassSpec { flag: "-pass" }],
        env [],
        OPENSSL_MIG
    ),
    tool!(
        "docker",
        &["podman", "nerdctl"],
        None,
        rules [
            ArgRule::Flag { flag: "-p", form: Form::Separate, kind: SecretKind::Password },
            ArgRule::Flag { flag: "--password", form: Form::Both, kind: SecretKind::Password },
        ],
        env [
            EnvRule { name: "DOCKER_PASSWORD", kind: SecretKind::Password, recommended: false },
        ],
        DOCKER_MIG
    ),
    tool!(
        "kubectl",
        &["oc"],
        Some("kubernetes"),
        rules [
            ArgRule::Flag { flag: "--token", form: Form::Both, kind: SecretKind::Token },
            ArgRule::Flag { flag: "--password", form: Form::Both, kind: SecretKind::Password },
        ],
        env [],
        ARGV_LAST_RESORT
    ),
    tool!(
        "git",
        &[],
        Some("git"),
        rules [ArgRule::UrlUserInfo],
        env [],
        GIT_MIG
    ),
    tool!(
        "smbclient",
        &["mount.cifs", "smbpasswd"],
        None,
        rules [
            ArgRule::PercentUserPass { flag: "-U" },
            ArgRule::PercentUserPass { flag: "--user" },
        ],
        env [
            EnvRule { name: "PASSWD", kind: SecretKind::Password, recommended: false },
        ],
        SMB_MIG
    ),
    tool!(
        "lftp",
        &["ftp"],
        None,
        rules [
            ArgRule::CommaUserPass { flag: "-u" },
            ArgRule::UrlUserInfo,
        ],
        env [],
        ARGV_LAST_RESORT
    ),
    tool!(
        "aws",
        &[],
        Some("aws"),
        rules [],
        env [
            EnvRule { name: "AWS_SECRET_ACCESS_KEY", kind: SecretKind::SecretAccessKey, recommended: false },
            EnvRule { name: "AWS_SESSION_TOKEN", kind: SecretKind::SessionToken, recommended: false },
            EnvRule { name: "AWS_ACCESS_KEY_ID", kind: SecretKind::AccessKeyId, recommended: false },
        ],
        AWS_MIG
    ),
    tool!(
        "keytool",
        &["jarsigner"],
        None,
        rules [
            ArgRule::Flag { flag: "-storepass", form: Form::Separate, kind: SecretKind::Password },
            ArgRule::Flag { flag: "-keypass", form: Form::Separate, kind: SecretKind::Password },
        ],
        env [],
        KEYTOOL_MIG
    ),
    tool!(
        "zip",
        &["7z", "7za"],
        None,
        rules [ArgRule::Flag { flag: "-P", form: Form::Separate, kind: SecretKind::Passphrase }],
        env [],
        ARGV_LAST_RESORT
    ),
    tool!(
        "mosquitto_pub",
        &["mosquitto_sub"],
        Some("mqtt"),
        rules [ArgRule::Flag { flag: "-P", form: Form::Separate, kind: SecretKind::Password }],
        env [],
        ARGV_LAST_RESORT
    ),
    tool!(
        "clickhouse-client",
        &["clickhouse"],
        None,
        rules [ArgRule::Flag { flag: "--password", form: Form::Both, kind: SecretKind::Password }],
        env [],
        ARGV_LAST_RESORT
    ),
    tool!(
        "pscp",
        &["plink"],
        None,
        rules [
            ArgRule::Flag { flag: "-pw", form: Form::Separate, kind: SecretKind::Password },
            ArgRule::UrlUserInfo,
        ],
        env [],
        ARGV_LAST_RESORT
    ),
    tool!(
        "svn",
        &[],
        None,
        rules [
            ArgRule::Flag { flag: "--password", form: Form::Both, kind: SecretKind::Password },
        ],
        env [],
        ARGV_LAST_RESORT
    ),
    tool!(
        "htpasswd",
        &[],
        None,
        rules [ArgRule::LastPositional { flag: "-b" }],
        env [],
        ARGV_LAST_RESORT
    ),
    tool!(
        "ansible-playbook",
        &["ansible"],
        None,
        rules [ArgRule::ExtraVars { flag: "--extra-vars" }],
        env [],
        ANSIBLE_MIG
    ),
    tool!(
        "vault",
        &[],
        Some("hashicorp"),
        rules [],
        env [
            EnvRule { name: "VAULT_TOKEN", kind: SecretKind::Token, recommended: false },
        ],
        ARGV_LAST_RESORT
    ),
    tool!(
        "influx",
        &[],
        None,
        rules [ArgRule::Flag { flag: "-password", form: Form::Both, kind: SecretKind::Password }],
        env [],
        ARGV_LAST_RESORT
    ),
];

/// Registration for a tool whose credential appears in a key/value payload
/// rather than a dedicated option.
const ANSIBLE_MIG: Migration = Migration {
    channel: Channel::ProtectedFile,
    snippet: concat!(
        "# keep variables in an encrypted, mode-0600 file and pass it by reference:\n",
        "ansible-playbook site.yml --extra-vars @{PATH}\n",
        "# or use ansible-vault: ansible-playbook site.yml --ask-vault-pass"
    ),
    caveats: &[
        "an inline --extra-vars string is stored in the process arguments and in shell history",
        "an @file argument is read by ansible and never appears as a value",
    ],
    residual: "variables in a protected file",
};

/// How sensitive a key name is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyClass {
    /// The key names a credential (`password`, `db-password`, `api_key`).
    Strong,
    /// The key might name a credential (`key`, `auth`, `token` is strong but
    /// `signing` is weak); a value must also look secret.
    Weak,
    /// The key names a pointer to the secret (`password-file`, `token-path`).
    Reference,
    None,
}

fn split_words(k: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in k.chars() {
        if c.is_ascii_alphanumeric() {
            if c.is_ascii_uppercase() && prev_lower && !cur.is_empty() {
                words.push(std::mem::take(&mut cur));
            }
            prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
            cur.push(c.to_ascii_lowercase());
        } else {
            if !cur.is_empty() {
                words.push(std::mem::take(&mut cur));
            }
            prev_lower = false;
        }
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words
}

fn word_is_credential(w: &str) -> bool {
    STRONG_KEY_WORDS.contains(&w) || WEAK_KEY_WORDS.contains(&w)
}

fn is_strong_word(w: &str) -> bool {
    STRONG_KEY_WORDS.contains(&w)
}

fn is_weak_word(w: &str) -> bool {
    WEAK_KEY_WORDS.contains(&w)
}

/// Classify a key name (`--db-password`, `DB_PASSWORD_FILE`, `apiKey`, ...).
pub fn key_sensitivity(key: &str) -> KeyClass {
    let k = key.trim_start_matches('-');
    let words = split_words(k);
    if words.is_empty() {
        return KeyClass::None;
    }
    // A trailing reference word turns the key into a pointer, even when a
    // credential word precedes it (`--token-file`, `--password-path`).
    if let Some(last) = words.last() {
        if REFERENCE_SUFFIXES.iter().any(|s| *s == last) && words.len() >= 2 {
            return KeyClass::Reference;
        }
    }
    // Glued and camel-cased forms: `dbpassword`, `apikey`, `secretKey`.
    let joined: String = words.concat();
    let mut strong = words.iter().any(|w| is_strong_word(w));
    let weak = words.iter().any(|w| is_weak_word(w));
    if !strong && STRONG_KEY_WORDS.iter().any(|s| joined.ends_with(s) && s.len() >= 4) {
        strong = true;
    }
    // Adjacent bigrams: `api` + `key`, `private` + `key`, `connection` + `string`.
    if !strong {
        for pair in words.windows(2) {
            let bigram = format!("{}{}", pair[0], pair[1]);
            if STRONG_KEY_WORDS.iter().any(|s| *s == bigram) {
                strong = true;
                break;
            }
        }
    }
    if strong {
        KeyClass::Strong
    } else if weak || word_is_credential(&joined) {
        // `joined` catches nothing extra today but keeps single glued weak
        // words (`auth`) classified rather than dropped.
        if is_strong_word(&joined) {
            KeyClass::Strong
        } else {
            KeyClass::Weak
        }
    } else if REFERENCE_SUFFIXES.iter().any(|s| *s == joined) {
        KeyClass::Reference
    } else {
        KeyClass::None
    }
}

pub fn find_tool(program: &str) -> Option<&'static ToolSpec> {
    let base = crate::scan::sh::basename(program).to_ascii_lowercase();
    let base = base.strip_suffix(".exe").unwrap_or(&base);
    TOOLS
        .iter()
        .find(|t| t.name.eq_ignore_ascii_case(base) || t.aliases.iter().any(|a| a.eq_ignore_ascii_case(base)))
}

/// Look up the migration for a known program, if any.
pub fn migration_for(program: Option<&str>) -> Option<&'static Migration> {
    program.and_then(find_tool).map(|t| &t.migration)
}

/// Environment variables that are credentials regardless of the tool.
pub static GENERIC_ENV: &[EnvRule] = &[
    EnvRule { name: "HTTP_PROXY", kind: SecretKind::OpaqueCredential, recommended: false },
    EnvRule { name: "HTTPS_PROXY", kind: SecretKind::OpaqueCredential, recommended: false },
    EnvRule { name: "GITHUB_TOKEN", kind: SecretKind::Token, recommended: false },
    EnvRule { name: "GH_TOKEN", kind: SecretKind::Token, recommended: false },
    EnvRule { name: "GITLAB_TOKEN", kind: SecretKind::Token, recommended: false },
    EnvRule { name: "NPM_TOKEN", kind: SecretKind::Token, recommended: false },
    EnvRule { name: "DOCKER_PASSWORD", kind: SecretKind::Password, recommended: false },
    EnvRule { name: "SMTP_PASSWORD", kind: SecretKind::Password, recommended: false },
    EnvRule { name: "ARTIFACTORY_PASSWORD", kind: SecretKind::Password, recommended: false },
];

pub fn env_rule(name: &str) -> Option<&'static EnvRule> {
    let upper = name.to_ascii_uppercase();
    GENERIC_ENV
        .iter()
        .chain(TOOLS.iter().flat_map(|t| t.env.iter()))
        .find(|r| r.name.eq_ignore_ascii_case(&upper))
}

/// Word-level tokens that, on their own, mark a key as credential-bearing.
/// Matching is per word after splitting on `_`, `-` and `.`, so `--bypass` and
/// `--compass` do not match `pass`, while `--db_password` does.
pub static STRONG_KEY_WORDS: &[&str] = &[
    "password", "passwd", "passphrase", "pwd", "passwort", "motdepasse",
    "secret", "secretkey", "apikey", "token", "credential", "credentials",
    "creds", "bearer", "privatekey", "connectionstring", "connstr", "dsn",
];

/// Words that only mean "credential" when combined with another word, e.g.
/// `access` + `key`, or `private` + `key`.
pub static WEAK_KEY_WORDS: &[&str] = &["key", "auth", "access", "session", "client", "signing"];

/// Key suffixes that mark the value as a *reference* rather than a secret.
pub static REFERENCE_SUFFIXES: &[&str] = &[
    "file", "path", "fd", "env", "cmd", "command", "helper", "from", "store",
    "dir", "id", "name", "user", "username", "type", "format", "source",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_tools_by_name_and_alias() {
        assert_eq!(find_tool("mysql").unwrap().name, "mysql");
        assert_eq!(find_tool("/usr/bin/mysqldump").unwrap().name, "mysqldump");
        assert_eq!(find_tool("mariadb").unwrap().name, "mysql");
        assert!(find_tool("ls").is_none());
    }

    #[test]
    fn env_rules_resolve() {
        assert!(env_rule("PGPASSWORD").is_some());
        assert!(env_rule("REDISCLI_AUTH").unwrap().recommended);
        assert!(env_rule("PATH").is_none());
    }

    #[test]
    fn every_tool_has_a_migration() {
        for t in TOOLS {
            assert!(!t.migration.snippet.is_empty(), "{}", t.name);
            assert_ne!(t.migration.channel, Channel::None, "{}", t.name);
        }
    }
}
