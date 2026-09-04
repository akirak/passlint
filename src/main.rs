use passlint::LoadedConfig;
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(error) => {
            eprintln!("passlint: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<bool, passlint::Error> {
    let current_dir =
        env::current_dir().map_err(|error| passlint::Error::Walk(".".into(), error))?;
    let config = LoadedConfig::discover(&current_dir)?;
    let paths: Vec<PathBuf> = env::args_os().skip(1).map(PathBuf::from).collect();
    let violations = if paths.is_empty() {
        config.scan_all()?
    } else {
        config.check_paths(paths.iter())
    };
    if violations.is_empty() {
        eprintln!("OK");
    } else {
        eprintln!(
            "Error: {} violation{} found",
            violations.len(),
            if violations.len() == 1 { "" } else { "s" }
        );
        for violation in &violations {
            eprintln!("{}", violation.path.display());
        }
    }
    Ok(violations.is_empty())
}
