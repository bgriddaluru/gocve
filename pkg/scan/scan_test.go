package scan

import (
	"reflect"
	"slices"
	"testing"

	"github.com/bgriddaluru/gocve/pkg/models"
)

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
