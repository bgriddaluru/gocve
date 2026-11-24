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