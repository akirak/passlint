# passlint

`passlint` checks password-store filenames against path rules defined in a
`passlint.toml` file. It works with stores managed by tools such as
[`pass`](https://www.passwordstore.org/) and
[`passage`](https://github.com/FiloSottile/passage).

## Installation

### Using Cargo

Build the executable from this repository:

```console
cargo build --release
```

The executable is written to `target/release/passlint`. To install it into
Cargo's binary directory instead, run:

```console
cargo install --path .
```

### Using Nix

If you are using Nix with flakes enabled, build the default package:

```console
nix build -L
```

## Configuration

Create `passlint.toml` at the root of the password-store repository:

```toml
[store]
basedir = "store"
extension = ".age"

[paths]
allowed = [
  "infra/aws/<environment>/*",
]

[fields.environment]
allowed = ["dev", "stage", "prod"]
```

The settings have the following meanings:

- `store.basedir` — the password directory relative to the directory that
  contains `passlint.toml`. Defaults to the repository root when omitted.
- `store.extension` — the extension used by password files, including its
  leading dot, such as `.gpg` or `.age`.
- `paths.allowed` — the accepted paths relative to `store.basedir`, with the
  configured extension removed. Within a pattern:
  - A complete path segment written as `<name>` refers to `fields.name`.
  - `*` matches any characters within one path segment, and `?` matches one
    character. Wildcards do not cross `/` separators.
- `fields.name.allowed` — the exact values accepted for the corresponding
  `<name>` segment.

For the example above, `store/infra/aws/dev/database.age` is valid, while
`store/infra/aws/production/database.age` is not.

## Usage

Run `passlint` from the repository or one of its subdirectories to check every
password file under the configured base directory:

```console
passlint
```

The program searches the current directory and its parents for `passlint.toml`.

To check only new or modified files, pass their repository-relative paths as
arguments:

```console
passlint store/infra/aws/dev/database.age store/infra/aws/prod/api.age
```

Paths outside `store.basedir` and files without `store.extension` are ignored.
This allows a hook to pass every changed file without additional filtering.

### Adding a Git hook

You can run the check as a pre-commit hook in the Git repository. First,
create an executable script at `hooks/pre-commit`:

```sh
#!/bin/sh
git diff --cached --name-only --diff-filter=AM -z | xargs -0 -r passlint
```

Then register the script with Git. On Git 2.54 or newer, use config-based
hooks:

```console
git config --local hook.passlint.event pre-commit
git config --local hook.passlint.command ./hooks/pre-commit
```

On older versions of Git, set the entire hooks directory instead:

```console
git config --local core.hooksPath hooks
```

## Exit status

| Code | Meaning |
| ---- | ------- |
| `0` | Every checked password path is valid. |
| `1` | One or more password paths violate the configured rules. Diagnostics are printed to standard error. |
| `2` | The configuration could not be found or parsed, or a filesystem or configuration error occurred. |
