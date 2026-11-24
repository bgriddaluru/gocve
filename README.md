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

### Download a binary

Download an archive from [GitHub Releases](https://github.com/bgriddaluru/gocve/releases)
for your operating system (`windows`, `linux`, or `darwin` for macOS) and
architecture (`amd64` for x86-64 or `arm64`). Extract it and add the executable's
directory to `PATH`.

Windows archives use `.zip`; Linux and macOS archives use `.tar.gz`. Each release
includes `checksums.txt` with SHA-256 hashes for verifying the downloads.

Go is not required to run scans with a prebuilt binary. Remediation requires
`go` on `PATH` and a toolchain compatible with the target project's modules.

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

Display the installed version:

```powershell
gocve --version
```

Release binaries report the release version; local builds report `dev`.

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
| `--json-output` | None | Also write a JSON report to the specified file, overwriting an existing report. |
| `--ignore-unfixed` | `false` | Exclude findings without a known fixed version. |
| `--ignore-unknown-severity` | `false` | Exclude findings with missing or unknown severity. |
| `-h`, `--help` | | Show command help. |

```powershell
gocve --help
gocve scan --help
gocve remediate --help
```

### JSON reports for scripts

Tables and progress messages remain enabled. Use `--json-output` to also save a
separate machine-readable report:

```powershell
gocve scan --json-output scan-results.json
gocve remediate --json-output remediation-results.json
```

The destination's parent directory must already exist. Use a dedicated report
path, not an existing project file: an existing destination is overwritten.
Before doing any work, the command writes an initial report with
`"completed": false`, replacing stale results and checking the destination.
Final reports are written through a temporary file in the same directory and
renamed into place. An unwritable destination fails the command before scanning
or remediation starts; a later report-writing failure also returns an error.
An interrupted command may leave the initial incomplete report.

Both reports have `schema_version`, `command`, `completed`, and `errors` fields.
Errors include a `stage`, `message`, and relevant `module` or `package`.
Empty lists are `[]`, not `null`.

Scan reports contain `modules`, including successfully scanned modules without
findings. Findings reflect the command's ignore flags:

```json
{
  "schema_version": 1,
  "command": "scan",
  "completed": true,
  "errors": [],
  "modules": [
    {
      "path": "/src/myrepo",
      "findings": [
        {
          "package": "example.com/dependency",
          "installed_version": "v1.0.0",
          "vulnerability_id": "CVE-2026-1234",
          "severity": "HIGH",
          "fixed_version": "v1.2.0",
          "aliases": ["CVE-2026-1234", "GO-2026-0001"]
        }
      ]
    }
  ]
}
```

Remediation reports contain `changes` and `skipped`:

```json
{
  "schema_version": 1,
  "command": "remediate",
  "completed": true,
  "errors": [],
  "changes": [
    {
      "module": "/src/myrepo",
      "package": "example.com/dependency",
      "previous_version": "v1.0.0",
      "requested_version": "v1.2.0",
      "resolved_version": "v1.3.0",
      "removed": false,
      "vulnerability_ids": ["CVE-2026-1234"]
    }
  ],
  "skipped": []
}
```

Each change groups successful `go get` requests by module and package.
`previous_version` is the scanned version, `requested_version` is the last
successfully requested upgrade target, and `resolved_version` is the selected
module version reported by `go list -m -json all` after processing, including tidy
and workspace sync. If tidy removes an unused dependency, `removed` is `true`
and `resolved_version` is `null`. The resolved version is also `null` if version
resolution fails, in which case the report includes an error. Other dependencies
changed indirectly by Go are not enumerated.

Skipped findings include `module`, `package`, `vulnerability_id`, and a reason:
`no_fixed_version` or `unknown_severity`. Findings excluded by ignore flags are
not included in this list.

On execution failure, the report preserves earlier results with
`"completed": false`, and the command exits nonzero. Errors identify the failing
stage, such as `scan`, `upgrade`, `tidy`, `workspace_sync`, or `resolve_versions`.
`"completed": true` means execution completed, not that the repository is free
of vulnerabilities. Upgrades are not automatically verified with another scan.
A successful scan still exits zero even when it finds vulnerabilities.

PowerShell:

```powershell
gocve remediate --json-output remediation-results.json
$exitCode = $LASTEXITCODE
$result = Get-Content -Raw remediation-results.json | ConvertFrom-Json
$result.changes | Select-Object package, previous_version, resolved_version
if ($exitCode -ne 0) { Write-Warning "Command failed; inspect completed and errors." }
```

Linux (requires `jq`):

```bash
gocve remediate --json-output remediation-results.json
status=$?
jq '.changes[] | {package, previous_version, resolved_version}' remediation-results.json
if [ "$status" -ne 0 ]; then
    echo "Command failed; inspect completed and errors." >&2
fi
```

Always check command errors: if the report could not be written, do not treat an
existing file as the current result.

## Publishing a release

Releases are built by [GitHub Actions](.github/workflows/release.yml) using
[GoReleaser](.goreleaser.yaml). No Makefile or manually configured token is
required; the workflow uses GitHub's automatic `GITHUB_TOKEN`.

1. Commit and push the release configuration and any code changes to GitHub.
   Ensure GitHub Actions is enabled in the repository's **Settings > Actions >
   General** and repository policies allow the workflow's `contents: write`
   permission.
2. Run `go test ./...` and resolve any failures before releasing. The workflow
   also runs tests and will not publish if they fail.
3. Tag the commit you want to release with a new semantic version and push it:

   ```powershell
   git tag v0.1.0
   git push origin v0.1.0
   ```

4. Follow the **Release** workflow in the repository's **Actions** tab. On
   success, the **Releases** page will contain six archives covering Windows,
   Linux, and macOS on AMD64 and ARM64, plus SHA-256 checksums. The archives
   include the executable, README, and license.

Use a new version tag for each release. Tags such as `v0.2.0-rc.1` are published
as prereleases automatically.

For a local packaging check, install
[GoReleaser v2.20.3](https://github.com/goreleaser/goreleaser/releases/tag/v2.20.3)
and run from the repository root:

```powershell
goreleaser check
goreleaser release --snapshot --clean
```

Snapshot mode creates archives and checksums in `dist` without publishing a
GitHub Release. It does not run the workflow's test step; run tests separately.