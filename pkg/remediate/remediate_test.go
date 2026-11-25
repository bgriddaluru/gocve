package remediate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bgriddaluru/gocve/pkg/models"
	"github.com/bgriddaluru/gocve/pkg/utils/logger"
)

type moduleScannerFunc func(context.Context, string) (map[string]*models.PackageVulnerability, error)

func (f moduleScannerFunc) ScanModule(ctx context.Context, path string) (map[string]*models.PackageVulnerability, error) {
	return f(ctx, path)
}

func testRemediator(t *testing.T) *Remediator {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/test\n\ngo 1.27.4\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return NewRemediator(models.Config{Path: root})
}

func remediationFindings() map[string]*models.PackageVulnerability {
	return map[string]*models.PackageVulnerability{
		"a": {
			PackageName: "example.com/a", InstalledVersion: "v1.0.0",
			VulnSummary: map[string]*models.PackageVulnerabilitySummary{
				"GO-A": {ID: "GO-A", Severity: "HIGH", FixedVersion: "1.2.0"},
				"GO-B": {ID: "GO-B", Severity: "HIGH", FixedVersion: "v1.3.0"},
			},
		},
		"b": {
			PackageName: "example.com/b", InstalledVersion: "v1.0.0",
			VulnSummary: map[string]*models.PackageVulnerabilitySummary{
				"GO-C": {ID: "GO-C", Severity: "HIGH"},
				"GO-D": {ID: "GO-D", Severity: "UNKNOWN", FixedVersion: "v1.2.0"},
			},
		},
	}
}

func TestRemediationResult(t *testing.T) {
	r := testRemediator(t)
	r.scanner = moduleScannerFunc(func(context.Context, string) (map[string]*models.PackageVulnerability, error) {
		return remediationFindings(), nil
	})
	var commands []string
	r.runGo = func(_ context.Context, _ *logger.Logger, dir string, args ...string) ([]byte, error) {
		if dir != r.config.Path {
			t.Fatalf("unexpected module: %s", dir)
		}
		commands = append(commands, strings.Join(args, " "))
		if args[0] == "list" {
			return []byte(`{"Path":"example.com/a","Version":"v1.4.0"}`), nil
		}
		return nil, nil
	}
	result, err := r.Remediate(context.Background())
	if err != nil || !result.Completed || len(result.Errors) != 0 || len(result.Changes) != 1 || len(result.Skipped) != 2 {
		t.Fatalf("unexpected result: %+v, %v", result, err)
	}
	change := result.Changes[0]
	if change.Module != r.config.Path || change.Package != "example.com/a" ||
		change.PreviousVersion != "v1.0.0" || change.RequestedVersion != "v1.3.0" ||
		change.ResolvedVersion == nil || *change.ResolvedVersion != "v1.4.0" ||
		!reflect.DeepEqual(change.VulnerabilityIDs, []string{"GO-A", "GO-B"}) {
		t.Fatalf("incorrect change: %+v", change)
	}
	if result.Skipped[0].Reason != "no_fixed_version" || result.Skipped[1].Reason != "unknown_severity" {
		t.Fatalf("incorrect skip reasons: %+v", result.Skipped)
	}
	want := []string{
		"mod download example.com/a@v1.2.0", "get example.com/a@v1.2.0",
		"mod download example.com/a@v1.3.0", "get example.com/a@v1.3.0",
		"mod tidy", "list -m -json all",
	}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("commands = %v, want %v", commands, want)
	}
}

func TestRemediationPartialResults(t *testing.T) {
	for _, stage := range []string{"upgrade", "tidy", "workspace_sync", "resolve_versions"} {
		t.Run(stage, func(t *testing.T) {
			r := testRemediator(t)
			if stage == "workspace_sync" {
				if err := os.WriteFile(filepath.Join(r.config.Path, "go.work"), []byte("go 1.27.4\nuse .\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			r.scanner = moduleScannerFunc(func(context.Context, string) (map[string]*models.PackageVulnerability, error) {
				return remediationFindings(), nil
			})
			failure := errors.New("operation failed")
			r.runGo = func(_ context.Context, _ *logger.Logger, _ string, args ...string) ([]byte, error) {
				if (stage == "upgrade" && args[0] == "get" && args[1] == "example.com/a@v1.3.0") ||
					(stage == "tidy" && args[0] == "mod" && args[1] == "tidy") ||
					(stage == "workspace_sync" && args[0] == "work") ||
					(stage == "resolve_versions" && args[0] == "list") {
					return nil, failure
				}
				if args[0] == "list" {
					return []byte(`{"Path":"example.com/a","Version":"v1.2.0"}`), nil
				}
				return nil, nil
			}
			result, err := r.Remediate(context.Background())
			if !errors.Is(err, failure) || result.Completed || len(result.Changes) != 1 ||
				len(result.Errors) != 1 || result.Errors[0].Stage != stage {
				t.Fatalf("partial results lost: %+v, %v", result, err)
			}
			change := result.Changes[0]
			if (change.ResolvedVersion == nil) != (stage == "resolve_versions") {
				t.Fatalf("unexpected resolved version: %+v", change)
			}
			if stage == "upgrade" && !reflect.DeepEqual(change.VulnerabilityIDs, []string{"GO-A"}) {
				t.Fatalf("failed upgrade was reported as successful: %+v", change)
			}
		})
	}
}

func TestRemediationVersionResolutionErrors(t *testing.T) {
	for _, output := range []string{"not JSON", "", `{}`, `{"Path":"example.com/a"}`} {
		t.Run(output, func(t *testing.T) {
			r := testRemediator(t)
			r.scanner = moduleScannerFunc(func(context.Context, string) (map[string]*models.PackageVulnerability, error) {
				return remediationFindings(), nil
			})
			r.runGo = func(_ context.Context, _ *logger.Logger, _ string, args ...string) ([]byte, error) {
				if args[0] == "list" {
					return []byte(output), nil
				}
				return nil, nil
			}
			result, err := r.Remediate(context.Background())
			if err == nil || result.Completed || len(result.Errors) != 1 ||
				result.Errors[0].Stage != "resolve_versions" || result.Changes[0].ResolvedVersion != nil {
				t.Fatalf("version resolution failure hidden: %+v, %v", result, err)
			}
		})
	}
}

func TestRemediationReportsDependencyRemovedByTidy(t *testing.T) {
	r := testRemediator(t)
	r.scanner = moduleScannerFunc(func(context.Context, string) (map[string]*models.PackageVulnerability, error) {
		return remediationFindings(), nil
	})
	r.runGo = func(_ context.Context, _ *logger.Logger, _ string, args ...string) ([]byte, error) {
		if args[0] == "list" {
			return []byte(`{"Path":"example.com/test","Main":true}`), nil
		}
		return nil, nil
	}
	result, err := r.Remediate(context.Background())
	if err != nil || !result.Completed || len(result.Changes) != 1 ||
		!result.Changes[0].Removed || result.Changes[0].ResolvedVersion != nil {
		t.Fatalf("removed dependency was not reported: %+v, %v", result, err)
	}
}

func TestRemediationWithNoUpgrades(t *testing.T) {
	for _, skipped := range []bool{false, true} {
		name := "empty"
		if skipped {
			name = "all skipped"
		}
		t.Run(name, func(t *testing.T) {
			r := testRemediator(t)
			r.scanner = moduleScannerFunc(func(context.Context, string) (map[string]*models.PackageVulnerability, error) {
				findings := make(map[string]*models.PackageVulnerability)
				if skipped {
					findings["b"] = remediationFindings()["b"]
				}
				return findings, nil
			})
			r.runGo = func(_ context.Context, _ *logger.Logger, _ string, args ...string) ([]byte, error) {
				if !reflect.DeepEqual(args, []string{"mod", "tidy"}) {
					t.Fatalf("unexpected command without upgrades: %v", args)
				}
				return nil, nil
			}
			result, err := r.Remediate(context.Background())
			wantSkipped := 0
			if skipped {
				wantSkipped = 2
			}
			if err != nil || !result.Completed || result.Changes == nil || len(result.Changes) != 0 ||
				result.Skipped == nil || len(result.Skipped) != wantSkipped || result.Errors == nil || len(result.Errors) != 0 {
				t.Fatalf("unexpected result without upgrades: %+v, %v", result, err)
			}
		})
	}
}
