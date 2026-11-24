# gocve

Scan Go repositories for known dependency vulnerabilities and upgrade affected
dependencies to reported fixed versions.

## What it does

- Recursively discovers Go modules (`go.mod`) and workspaces (`go.work`).
- Checks direct and indirect dependencies listed in each module's `go.mod`
  against the [OSV vulnerability database](https://osv.dev/).
- Displays findings in a table with vulnerability ID, severity, package,
  installed version, and fixed version.
- Remediates eligible findings with `go get`, runs `go mod tidy` for updated
  modules, and runs `go work sync` for affected workspaces.

Scanning checks dependency versions, not whether vulnerable code is actually
reachable in your application. It requires network access to the OSV API and
sends dependency module paths and versions to that service.

## Installation

### Install with Go

```powershell
go install github.com/bgriddaluru/gocve@latest
```

Add your Go binary installation directory to `PATH`: `GOBIN` if configured,
otherwise the `bin` directory under `GOPATH` (typically `%USERPROFILE%\go\bin`
on Windows).

### Build from source

```powershell
git clone https://github.com/bgriddaluru/gocve.git
cd gocve
go build -o gocve.exe .
.\gocve.exe --help
```

The examples below use `gocve` installed on `PATH`. If you built locally, use
`.\gocve.exe` instead.

## Usage

### Scan

Scan the current directory and its subdirectories:

```powershell
gocve scan
```

Scan a specific repository, skipping directories by name:

```powershell
gocve scan --path "C:\src\myrepo" --skip-dirs vendor,testdata
```

Show only findings with a known fix and known severity:

```powershell
gocve scan --ignore-unfixed --ignore-unknown-severity
```

### Remediate

Commit or back up your changes first. Remediation modifies dependency files
without an interactive confirmation and may update other dependencies through
Go's module resolution.

```powershell
gocve remediate --path "C:\src\myrepo"
```

Remediation scans first, then attempts upgrades for findings with a reported
fixed version and a severity other than `UNKNOWN`. Findings without a known
fixed version or with `UNKNOWN` severity are skipped.

Afterward, review the dependency changes, run your project's tests, and scan
again to check for remaining findings:

```powershell
go test .\...
gocve scan
```

Run these checks from the target module directory; for multi-module repositories,
run the appropriate tests for each affected module.

### Flags

Both `scan` and `remediate` accept these flags:

| Flag | Default | Description |
| --- | --- | --- |
| `--path` | `.` | Root directory to search for Go modules and workspaces. |
| `--skip-dirs` | None | Directory names to skip, comma-separated or supplied through repeated flags. |
| `--debug` | `false` | Enable debug logging. |
| `--ignore-unfixed` | `false` | Exclude findings without a known fixed version. |
| `--ignore-unknown-severity` | `false` | Exclude findings with missing or unknown severity. |
| `-h`, `--help` | | Show command help. |

```powershell
gocve --help
gocve scan --help
gocve remediate --help
```