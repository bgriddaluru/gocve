package scan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/bgriddaluru/gocve/pkg/models"
)

type queryAdvisoryFunc func(context.Context, []models.Package) (map[string]*models.PackageVulnerability, error)

func (f queryAdvisoryFunc) QueryVulnerabilities(ctx context.Context, packages []models.Package) (map[string]*models.PackageVulnerability, error) {
	return f(ctx, packages)
}

func TestScanResultAndConsoleTable(t *testing.T) {
	if os.Getenv("GOCVE_TEST_SCAN_TABLE") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestScanResultAndConsoleTable$")
		cmd.Env = append(os.Environ(), "GOCVE_TEST_SCAN_TABLE=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("scan failed: %v\n%s", err, output)
		}
		for _, want := range []string{"CVE-2026-1234", "INSTALLED", "FIXED", "example.com/a"} {
			if !strings.Contains(string(output), want) {
				t.Fatalf("console table missing %q:\n%s", want, output)
			}
		}
		return
	}

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s := NewScanner(models.Config{Path: root, IgnoreUnfixed: true})
	s.advisory = queryAdvisoryFunc(func(context.Context, []models.Package) (map[string]*models.PackageVulnerability, error) {
		return map[string]*models.PackageVulnerability{
			"b": {
				PackageName: "example.com/b", InstalledVersion: "v2.0.0",
				VulnSummary: map[string]*models.PackageVulnerabilitySummary{
					"CVE-2026-9999": {Severity: "HIGH", FixedVersion: "v2.1.0"},
				},
			},
			"a": {
				PackageName: "example.com/a", InstalledVersion: "v1.0.0",
				VulnSummary: map[string]*models.PackageVulnerabilitySummary{
					"CVE-2026-1234": {Severity: "HIGH", FixedVersion: "v1.2.0", Aliases: []string{"GO-A", "CVE-2026-1234"}},
					"unfixed":       {Severity: "LOW"},
				},
			},
		}, nil
	})
	result, err := s.Scan(context.Background())
	if err != nil || !result.Completed || len(result.Modules) != 1 || len(result.Errors) != 0 {
		t.Fatalf("unexpected result: %+v, %v", result, err)
	}
	module := result.Modules[0]
	if module.Path != root || len(module.Findings) != 2 {
		t.Fatalf("unexpected module: %+v", module)
	}
	first := module.Findings[0]
	if first.Package != "example.com/a" || first.InstalledVersion != "v1.0.0" ||
		first.VulnerabilityID != "CVE-2026-1234" || first.FixedVersion != "v1.2.0" ||
		first.Severity != "HIGH" || !reflect.DeepEqual(first.Aliases, []string{"CVE-2026-1234", "GO-A"}) {
		t.Fatalf("unexpected finding: %+v", first)
	}
	if module.Findings[1].Aliases == nil {
		t.Fatal("empty aliases must be an array")
	}
}

func TestScanPartialModuleResults(t *testing.T) {
	root := t.TempDir()
	for _, module := range []struct{ name, content string }{
		{"a", "module example.com/a\n"},
		{"b", "not a valid go.mod\n"},
	} {
		dir := filepath.Join(root, module.name)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(module.content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	result, err := NewScanner(models.Config{Path: root}).Scan(context.Background())
	if err == nil || result.Completed || len(result.Modules) != 1 ||
		result.Modules[0].Path != filepath.Join(root, "a") || result.Modules[0].Findings == nil ||
		len(result.Errors) != 1 || result.Errors[0].Module != filepath.Join(root, "b") {
		t.Fatalf("unexpected partial result: %+v, %v", result, err)
	}
}

func TestFilterVulnerabilities(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config models.Config
		want   []string
	}{
		{
			name: "default preserves all findings",
			want: []string{"both", "empty-severity", "fixed-known", "lowercase-unknown", "unfixed", "unknown"},
		},
		{
			name:   "ignore unfixed",
			config: models.Config{IgnoreUnfixed: true},
			want:   []string{"empty-severity", "fixed-known", "lowercase-unknown", "unknown"},
		},
		{
			name:   "ignore unknown severity",
			config: models.Config{IgnoreUnknownSeverity: true},
			want:   []string{"fixed-known", "unfixed"},
		},
		{
			name:   "combine filters",
			config: models.Config{IgnoreUnfixed: true, IgnoreUnknownSeverity: true},
			want:   []string{"fixed-known"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vulns := map[string]*models.PackageVulnerability{
				"mixed": {
					PackageName:      "example.com/mixed",
					InstalledVersion: "1.0.0",
					VulnSummary: map[string]*models.PackageVulnerabilitySummary{
						"fixed-known":       {Severity: "HIGH", FixedVersion: "1.2.0"},
						"unfixed":           {Severity: "LOW"},
						"unknown":           {Severity: "UNKNOWN", FixedVersion: "1.2.0"},
						"lowercase-unknown": {Severity: "unknown", FixedVersion: "1.2.0"},
						"empty-severity":    {FixedVersion: "1.2.0"},
					},
				},
				"only-ignored": {
					VulnSummary: map[string]*models.PackageVulnerabilitySummary{
						"both": {Severity: "UNKNOWN"},
					},
				},
			}
			s := &Scanner{config: tc.config}
			s.filterVulnerabilities(vulns)
			var got []string
			for _, pkg := range vulns {
				if len(pkg.VulnSummary) == 0 {
					t.Fatal("package without findings was retained")
				}
				for id := range pkg.VulnSummary {
					got = append(got, id)
				}
			}
			slices.Sort(got)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("remaining findings = %v, want %v", got, tc.want)
			}
			if _, exists := vulns["only-ignored"]; exists != (!tc.config.IgnoreUnfixed && !tc.config.IgnoreUnknownSeverity) {
				t.Fatal("package removal did not match enabled filters")
			}
			pkg := vulns["mixed"]
			if pkg.PackageName != "example.com/mixed" || pkg.InstalledVersion != "1.0.0" {
				t.Fatal("filter changed package metadata")
			}
		})
	}
}
