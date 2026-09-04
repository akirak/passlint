use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

pub const CONFIG_FILE: &str = "passlint.toml";
const HOST_FIELD: &str = "host";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    store: Store,
    paths: Paths,
    #[serde(default)]
    fields: BTreeMap<String, Field>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Store {
    #[serde(default)]
    basedir: PathBuf,
    extension: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Paths {
    allowed: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Field {
    allowed: Vec<String>,
}

#[derive(Debug)]
pub struct LoadedConfig {
    root: PathBuf,
    config: Config,
    patterns: Vec<Pattern>,
}

#[derive(Debug)]
struct Pattern {
    source: String,
    segments: Vec<Segment>,
}

#[derive(Debug)]
enum Segment {
    Glob(String),
    Field(String),
}

#[derive(Debug)]
pub enum Error {
    NoConfig(PathBuf),
    ReadConfig(PathBuf, std::io::Error),
    ParseConfig(PathBuf, toml::de::Error),
    InvalidConfig(String),
    Walk(PathBuf, std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoConfig(path) => write!(
                f,
                "could not find {CONFIG_FILE} in {} or any parent directory",
                path.display()
            ),
            Self::ReadConfig(path, error) => {
                write!(f, "could not read {}: {error}", path.display())
            }
            Self::ParseConfig(path, error) => {
                write!(f, "could not parse {}: {error}", path.display())
            }
            Self::InvalidConfig(message) => write!(f, "invalid configuration: {message}"),
            Self::Walk(path, error) => write!(f, "could not inspect {}: {error}", path.display()),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, PartialEq, Eq)]
pub struct Violation {
    pub path: PathBuf,
    pub message: String,
}

impl LoadedConfig {
    pub fn discover(start: &Path) -> Result<Self, Error> {
        let start = start
            .canonicalize()
            .map_err(|error| Error::Walk(start.to_path_buf(), error))?;
        let start_dir = if start.is_dir() {
            start.as_path()
        } else {
            start.parent().unwrap_or(start.as_path())
        };
        let config_path = start_dir
            .ancestors()
            .map(|directory| directory.join(CONFIG_FILE))
            .find(|candidate| candidate.is_file())
            .ok_or_else(|| Error::NoConfig(start_dir.to_path_buf()))?;
        Self::load(&config_path)
    }

    pub fn load(config_path: &Path) -> Result<Self, Error> {
        let contents = fs::read_to_string(config_path)
            .map_err(|error| Error::ReadConfig(config_path.to_path_buf(), error))?;
        let config: Config = toml::from_str(&contents)
            .map_err(|error| Error::ParseConfig(config_path.to_path_buf(), error))?;
        validate_config(&config)?;
        let patterns = config
            .paths
            .allowed
            .iter()
            .map(|pattern| parse_pattern(pattern))
            .collect::<Result<Vec<_>, _>>()?;
        for pattern in &patterns {
            for segment in &pattern.segments {
                if let Segment::Field(name) = segment
                    && name != HOST_FIELD
                    && !config.fields.contains_key(name)
                {
                    return Err(Error::InvalidConfig(format!(
                        "pattern {:?} refers to undefined field <{name}>",
                        pattern.source
                    )));
                }
            }
        }
        let root = config_path
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .canonicalize()
            .map_err(|error| Error::ReadConfig(config_path.to_path_buf(), error))?;
        Ok(Self {
            root,
            config,
            patterns,
        })
    }

    pub fn scan_all(&self) -> Result<Vec<Violation>, Error> {
        let store = self.root.join(&self.config.store.basedir);
        if !store.exists() {
            return Err(Error::InvalidConfig(format!(
                "store directory {} does not exist",
                store.display()
            )));
        }
        let mut files = Vec::new();
        collect_files(&store, &mut files)?;
        files.sort();
        Ok(self.check_paths(files.iter()))
    }

    pub fn check_paths<'a, I>(&self, paths: I) -> Vec<Violation>
    where
        I: IntoIterator<Item = &'a PathBuf>,
    {
        let mut violations = Vec::new();
        for supplied in paths {
            let absolute = if supplied.is_absolute() {
                supplied.clone()
            } else {
                self.root.join(supplied)
            };
            let Ok(relative_to_root) = absolute.strip_prefix(&self.root) else {
                continue;
            };
            let Ok(relative_to_store) = relative_to_root.strip_prefix(&self.config.store.basedir)
            else {
                continue;
            };
            if relative_to_store
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
            {
                continue;
            }
            let Some(path) = relative_to_store.to_str() else {
                violations.push(Violation {
                    path: relative_to_root.to_path_buf(),
                    message: "path is not valid UTF-8".into(),
                });
                continue;
            };
            let Some(without_extension) = path.strip_suffix(&self.config.store.extension) else {
                continue;
            };
            if without_extension.is_empty() {
                continue;
            }
            if let Some(message) = self.violation_for(without_extension) {
                violations.push(Violation {
                    path: PathBuf::from(without_extension),
                    message,
                });
            }
        }
        violations
    }

    fn violation_for(&self, path: &str) -> Option<String> {
        let segments: Vec<_> = path.split('/').collect();
        let mut bad_fields = Vec::new();
        for pattern in &self.patterns {
            if pattern.segments.len() != segments.len() {
                continue;
            }
            let mut fields_for_pattern = Vec::new();
            let mut shape_matches = true;
            for (rule, value) in pattern.segments.iter().zip(&segments) {
                match rule {
                    Segment::Glob(glob) if !glob_matches(glob, value) => {
                        shape_matches = false;
                        break;
                    }
                    Segment::Field(name) => {
                        let allowed = if name == HOST_FIELD {
                            host_matches(value)
                        } else {
                            self.config.fields[name]
                                .allowed
                                .iter()
                                .any(|allowed| allowed == value)
                        };
                        if !allowed {
                            fields_for_pattern.push(format!(
                                "field <{name}> has disallowed value {value:?} in pattern {:?}",
                                pattern.source
                            ));
                        }
                    }
                    Segment::Glob(_) => {}
                }
            }
            if shape_matches && fields_for_pattern.is_empty() {
                return None;
            }
            if shape_matches {
                bad_fields.extend(fields_for_pattern);
            }
        }
        bad_fields
            .into_iter()
            .next()
            .or_else(|| Some("path does not match any allowed pattern".into()))
    }
}

fn validate_config(config: &Config) -> Result<(), Error> {
    if config.store.extension.is_empty() {
        return Err(Error::InvalidConfig(
            "store.extension must not be empty".into(),
        ));
    }
    if config.store.extension.contains('/') || config.store.extension.contains('\\') {
        return Err(Error::InvalidConfig(
            "store.extension must not contain a path separator".into(),
        ));
    }
    if config.store.basedir.is_absolute()
        || config
            .store
            .basedir
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(Error::InvalidConfig(
            "store.basedir must be relative to the repository root".into(),
        ));
    }
    if config.paths.allowed.is_empty() {
        return Err(Error::InvalidConfig(
            "paths.allowed must contain at least one pattern".into(),
        ));
    }
    Ok(())
}

fn parse_pattern(source: &str) -> Result<Pattern, Error> {
    if source.is_empty() || source.starts_with('/') || source.ends_with('/') {
        return Err(Error::InvalidConfig(format!(
            "invalid allowed path pattern {source:?}"
        )));
    }
    let mut segments = Vec::new();
    for part in source.split('/') {
        let segment = if part.starts_with('<') || part.ends_with('>') {
            let Some(name) = part.strip_prefix('<').and_then(|p| p.strip_suffix('>')) else {
                return Err(Error::InvalidConfig(format!(
                    "malformed field in pattern {source:?}"
                )));
            };
            if name.is_empty()
                || !name
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '_')
            {
                return Err(Error::InvalidConfig(format!(
                    "invalid field name <{name}> in pattern {source:?}"
                )));
            }
            Segment::Field(name.to_owned())
        } else {
            Segment::Glob(part.to_owned())
        };
        segments.push(segment);
    }
    Ok(Pattern {
        source: source.to_owned(),
        segments,
    })
}

fn collect_files(directory: &Path, files: &mut Vec<PathBuf>) -> Result<(), Error> {
    let entries = fs::read_dir(directory).map_err(|error| Error::Walk(directory.into(), error))?;
    for entry in entries {
        let entry = entry.map_err(|error| Error::Walk(directory.into(), error))?;
        let file_type = entry
            .file_type()
            .map_err(|error| Error::Walk(entry.path(), error))?;
        if file_type.is_dir() {
            collect_files(&entry.path(), files)?;
        } else if file_type.is_file() {
            files.push(entry.path());
        }
    }
    Ok(())
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut previous = vec![false; value.len() + 1];
    previous[0] = true;
    for token in pattern {
        let mut current = vec![false; value.len() + 1];
        if *token == b'*' {
            current[0] = previous[0];
            for index in 1..=value.len() {
                current[index] = previous[index] || current[index - 1];
            }
        } else {
            for index in 1..=value.len() {
                current[index] =
                    previous[index - 1] && (*token == b'?' || *token == value[index - 1]);
            }
        }
        previous = current;
    }
    previous[value.len()]
}

fn host_matches(value: &str) -> bool {
    let (hostname, port) = match value.split_once(':') {
        Some((hostname, port)) => (hostname, Some(port)),
        None => (value, None),
    };

    if hostname.is_empty()
        || hostname.len() > 253
        || !hostname.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
        })
    {
        return false;
    }

    match port {
        None => true,
        Some(port) => {
            !port.is_empty()
                && port.bytes().all(|byte| byte.is_ascii_digit())
                && port.parse::<u16>().is_ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn glob_matches_within_one_segment() {
        assert!(glob_matches("*", "service"));
        assert!(glob_matches("prod-*", "prod-api"));
        assert!(glob_matches("??", "ab"));
        assert!(!glob_matches("prod-*", "stage-api"));
    }

    #[test]
    fn host_matches_hostname_with_optional_port() {
        for value in [
            "localhost",
            "example.com",
            "api-1.example.com",
            "127.0.0.1",
            "example.com:443",
            "localhost:0",
            "localhost:65535",
        ] {
            assert!(host_matches(value), "expected {value:?} to match");
        }

        for value in [
            "",
            ".example.com",
            "example..com",
            "-example.com",
            "example-.com",
            "example.com:",
            "example.com:http",
            "example.com:65536",
            "example.com:80:90",
            "[::1]:443",
        ] {
            assert!(!host_matches(value), "expected {value:?} not to match");
        }
    }

    #[test]
    fn parses_field_segments() {
        let pattern = parse_pattern("infra/aws/<environment>/*").unwrap();
        assert!(matches!(&pattern.segments[2], Segment::Field(name) if name == "environment"));
    }

    #[test]
    fn checks_the_documented_configuration() {
        let fixture = Fixture::new();
        fixture.write(
            CONFIG_FILE,
            r#"
[store]
basedir = "store"
extension = ".age"

[paths]
allowed = ["infra/aws/<environment>/*"]

[fields.environment]
allowed = ["dev", "stage", "prod"]
"#,
        );
        fixture.write("store/infra/aws/dev/database.age", "secret");
        fixture.write("store/infra/aws/production/database.age", "secret");
        fixture.write("store/unrelated.txt", "not a password");

        let config = LoadedConfig::load(&fixture.path.join(CONFIG_FILE)).unwrap();
        let violations = config.scan_all().unwrap();
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0].path,
            PathBuf::from("infra/aws/production/database")
        );
        assert!(violations[0].message.contains("<environment>"));
        assert!(violations[0].message.contains("production"));
    }

    #[test]
    fn checks_the_builtin_host_field() {
        let fixture = Fixture::new();
        fixture.write(
            CONFIG_FILE,
            r#"
[store]
extension = ".gpg"

[paths]
allowed = ["servers/<host>"]
"#,
        );

        let config = LoadedConfig::load(&fixture.path.join(CONFIG_FILE)).unwrap();
        let paths = [
            PathBuf::from("servers/example.com.gpg"),
            PathBuf::from("servers/example.com:443.gpg"),
            PathBuf::from("servers/-example.com.gpg"),
            PathBuf::from("servers/example.com:70000.gpg"),
        ];

        let violations = config.check_paths(paths.iter());
        assert_eq!(violations.len(), 2);
        assert!(
            violations
                .iter()
                .all(|violation| violation.message.contains("<host>"))
        );
    }

    #[test]
    fn explicit_paths_ignore_files_outside_the_store_and_other_extensions() {
        let fixture = Fixture::new();
        fixture.write(
            CONFIG_FILE,
            r#"
[store]
basedir = "passwords"
extension = ".gpg"

[paths]
allowed = ["personal/*"]
"#,
        );
        let config = LoadedConfig::load(&fixture.path.join(CONFIG_FILE)).unwrap();
        let paths = [
            PathBuf::from("README.md"),
            PathBuf::from("passwords/notes.txt"),
            PathBuf::from("passwords/work/account.gpg"),
        ];

        let violations = config.check_paths(paths.iter());
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].path, PathBuf::from("work/account"));
    }

    struct Fixture {
        path: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            loop {
                let nonce = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
                let path =
                    std::env::temp_dir().join(format!("passlint-{}-{nonce}", std::process::id()));
                match fs::create_dir(&path) {
                    Ok(()) => return Self { path },
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("could not create fixture {}: {error}", path.display()),
                }
            }
        }

        fn write(&self, relative: &str, contents: &str) {
            let path = self.path.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, contents).unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).unwrap();
        }
    }
}
