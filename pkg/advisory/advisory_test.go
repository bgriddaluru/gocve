package advisory

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"

	"github.com/bgriddaluru/gocve/pkg/models"
	"github.com/bgriddaluru/gocve/pkg/osvutils/fixedversion"
)

type aliasTestProvider struct {
	details map[string]models.OSV
	calls   []string
	err     error
}

func (p *aliasTestProvider) QueryPackageVulnerabilities(context.Context, []models.Package) (map[string]*models.PackageVulnerability, error) {
	return nil, errors.New("unexpected package query")
}

func (p *aliasTestProvider) GetVulnerability(_ context.Context, id string) (models.OSV, error) {
	p.calls = append(p.calls, id)
	if p.err != nil {
		return models.OSV{}, p.err
	}
	detail, ok := p.details[id]
	if !ok {
		return models.OSV{}, errors.New("unexpected vulnerability query: " + id)
	}
	return detail, nil
}

func TestEnrichWithVulnerabilityAliasesDeduplicates(t *testing.T) {
	for _, tc := range []struct {
		name    string
		aliases map[string][]string
		want    map[string][]string
	}{
		{
			name: "reciprocal aliases prefer alias-only CVE and remove repeated aliases",
			aliases: map[string][]string{
				"GHSA-example": {"GO-2026-6974", "CVE-2026-128085", "GO-2026-6974"},
				"GO-2026-6974": {"GHSA-example", "CVE-2026-128085"},
			},
			want: map[string][]string{
				"CVE-2026-128085": {"CVE-2026-128085", "GHSA-example", "GO-2026-6974"},
			},
		},
		{
			name: "one-sided alias",
			aliases: map[string][]string{
				"GHSA-example": {"GO-2026-6974"},
				"GO-2026-6974": nil,
			},
			want: map[string][]string{"GO-2026-6974": {"GHSA-example", "GO-2026-6974"}},
		},
		{
			name: "shared alias prefers CVE over GHSA",
			aliases: map[string][]string{
				"CVE-2026-128085": {"OSV-example"},
				"GHSA-example":    {"OSV-example"},
			},
			want: map[string][]string{
				"CVE-2026-128085": {"CVE-2026-128085", "GHSA-example", "OSV-example"},
			},
		},
		{
			name: "transitive bridge merges all findings",
			aliases: map[string][]string{
				"GO-2026-0001": {"CVE-2026-0001"},
				"GO-2026-0002": {"CVE-2026-0002"},
				"GHSA-bridge":  {"CVE-2026-0001", "CVE-2026-0002"},
			},
			want: map[string][]string{
				"CVE-2026-0001": {"CVE-2026-0001", "CVE-2026-0002", "GHSA-bridge", "GO-2026-0001", "GO-2026-0002"},
			},
		},
		{
			name: "unrelated findings remain separate",
			aliases: map[string][]string{
				"GO-2026-0001": {"CVE-2026-0001"},
				"GO-2026-0002": nil,
			},
			want: map[string][]string{
				"CVE-2026-0001": {"CVE-2026-0001", "GO-2026-0001"},
				"GO-2026-0002":  {"GO-2026-0002"},
			},
		},
		{
			name:    "single finding prefers alias-only CVE",
			aliases: map[string][]string{"GHSA-example": {"CVE-2026-128085"}},
			want:    map[string][]string{"CVE-2026-128085": {"CVE-2026-128085", "GHSA-example"}},
		},
		{
			name:    "alias-only Go preferred without CVE",
			aliases: map[string][]string{"GHSA-example": {"GO-2026-6974"}},
			want:    map[string][]string{"GO-2026-6974": {"GHSA-example", "GO-2026-6974"}},
		},
		{
			name:    "alias-only GHSA preferred over other identifiers",
			aliases: map[string][]string{"OSV-example": {"GHSA-example"}},
			want:    map[string][]string{"GHSA-example": {"GHSA-example", "OSV-example"}},
		},
		{
			name:    "GHSA preferred over other identifiers",
			aliases: map[string][]string{"GHSA-example": {"OSV-example"}, "OSV-example": nil},
			want:    map[string][]string{"GHSA-example": {"GHSA-example", "OSV-example"}},
		},
		{
			name:    "empty findings",
			aliases: map[string][]string{},
			want:    map[string][]string{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := &aliasTestProvider{details: make(map[string]models.OSV)}
			for id, aliases := range tc.aliases {
				provider.details[id] = models.OSV{Aliases: aliases}
			}
			packages := make(map[string]*models.PackageVulnerability)
			for _, pkg := range []struct{ name, version string }{
				{"go.opentelemetry.io/otel/sdk", "v1.45.0"},
				{"go.opentelemetry.io/otel/trace", "v1.45.0"},
				{"go.opentelemetry.io/otel/sdk", "v1.44.0"},
			} {
				summaries := make(map[string]*models.PackageVulnerabilitySummary)
				for id := range tc.aliases {
					summaries[id] = &models.PackageVulnerabilitySummary{ID: id, Aliases: []string{id}}
				}
				packages[pkg.name+"@"+pkg.version] = &models.PackageVulnerability{
					PackageName: pkg.name, InstalledVersion: pkg.version, VulnSummary: summaries,
				}
			}
			advisory := &Advisory{provider: provider}
			if err := advisory.EnrichWithVulnerabilityAliases(context.Background(), packages); err != nil {
				t.Fatal(err)
			}
			for key, pkg := range packages {
				got := make(map[string][]string)
				for id, summary := range pkg.VulnSummary {
					if summary.ID != id {
						t.Fatalf("%s: summary ID %q differs from key %q", key, summary.ID, id)
					}
					got[id] = summary.Aliases
				}
				if !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("%s: got %v, want %v", key, got, tc.want)
				}
			}
			var wantCalls []string
			for range packages {
				for id := range tc.aliases {
					wantCalls = append(wantCalls, id)
				}
			}
			sort.Strings(provider.calls)
			sort.Strings(wantCalls)
			if !reflect.DeepEqual(provider.calls, wantCalls) {
				t.Fatalf("queried %v, want %v", provider.calls, wantCalls)
			}
			for id := range tc.want {
				if _, ok := provider.details[id]; !ok {
					provider.details[id] = models.OSV{}
				}
			}
			if err := advisory.EnrichWithVulnerabilityAliases(context.Background(), packages); err != nil {
				t.Fatal(err)
			}
			for key, pkg := range packages {
				for id, summary := range pkg.VulnSummary {
					if !reflect.DeepEqual(summary.Aliases, tc.want[id]) {
						t.Fatalf("%s: repeated enrichment changed aliases for %s: %v", key, id, summary.Aliases)
					}
				}
			}
		})
	}
}

func TestEnrichWithVulnerabilityAliasesPropagatesError(t *testing.T) {
	wantErr := errors.New("provider unavailable")
	advisory := &Advisory{provider: &aliasTestProvider{err: wantErr}}
	packages := map[string]*models.PackageVulnerability{
		"example@v1.0.0": {
			VulnSummary: map[string]*models.PackageVulnerabilitySummary{"GO-2026-0001": {ID: "GO-2026-0001"}},
		},
	}
	if err := advisory.EnrichWithVulnerabilityAliases(context.Background(), packages); !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
	}
	if len(packages["example@v1.0.0"].VulnSummary) != 1 {
		t.Fatal("provider failure removed the finding")
	}
}

func TestFindVulnerabilityIDs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		id      string
		aliases []string
		wantGO  string
		wantCVE string
	}{
		{"Go primary", "GO-2026-6107", []string{"BIT-etcd", "CVE-2026-73500"}, "GO-2026-6107", "CVE-2026-73500"},
		{"CVE primary", "CVE-2026-73500", []string{"GHSA-example", "GO-2026-6107"}, "GO-2026-6107", "CVE-2026-73500"},
		{"both from aliases", "GHSA-example", []string{"GO-2026-6107", "CVE-2026-73500"}, "GO-2026-6107", "CVE-2026-73500"},
		{"prefer primary CVE", "CVE-2026-73500", []string{"CVE-2026-111497", "GO-2026-6107"}, "GO-2026-6107", "CVE-2026-73500"},
		{"prefer primary Go", "GO-2026-6107", []string{"GO-2026-6888", "CVE-2026-73500"}, "GO-2026-6107", "CVE-2026-73500"},
		{"first matching aliases", "GHSA-example", []string{"GO-2026-6107", "GO-2026-6888", "CVE-2026-73500", "CVE-2026-111497"}, "GO-2026-6107", "CVE-2026-73500"},
		{"missing Go", "CVE-2026-73500", nil, "", "CVE-2026-73500"},
		{"missing CVE", "GO-2026-6107", nil, "GO-2026-6107", ""},
		{"no matching prefixes", "GHSA-example", []string{"x-CVE-2026-73500", "x-GO-2026-6107"}, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			goID, cveID := findVulnerabilityIDs(tc.id, tc.aliases)
			if goID != tc.wantGO || cveID != tc.wantCVE {
				t.Fatalf("got (%q, %q), want (%q, %q)", goID, cveID, tc.wantGO, tc.wantCVE)
			}
		})
	}
}

func TestFindFixedVersion(t *testing.T) {
	const packageName = "go.etcd.io/etcd/client/pkg/v3"
	affected := []models.AffectedPackage{{
		Package: &models.VulnerabilityPackage{Ecosystem: "Go", Name: packageName},
		Ranges: []models.AffectedRange{{
			Type: "SEMVER",
			Events: []models.RangeEvent{
				{Introduced: "0"}, {Fixed: "3.5.33"},
				{Introduced: "3.6.0"}, {Fixed: "3.6.14"},
				{Introduced: "3.7.0-alpha.0"}, {Fixed: "3.7.1"},
			},
		}},
	}}
	for _, tc := range []struct {
		installed string
		want      string
	}{
		{"v3.5.32", "3.5.33"},
		{"3.6.0", "3.6.14"},
		{"v3.6.13", "3.6.14"},
		{"v3.7.0-alpha.0", "3.7.1"},
		{"v3.7.0-rc.1", "3.7.1"},
		{"v3.7.0", "3.7.1"},
		{"v3.5.33", ""},
		{"v3.6.14", ""},
		{"v3.7.1", ""},
		{"v3.8.0", ""},
	} {
		t.Run(tc.installed, func(t *testing.T) {
			got, err := fixedversion.Find(affected, packageName, tc.installed)
			if err != nil || got != tc.want {
				t.Fatalf("fixed version = %q, err = %v, want %q", got, err, tc.want)
			}
		})
	}
}

func TestFindFixedVersionFiltersAndBoundaries(t *testing.T) {
	const packageName = "example.com/module"
	for _, tc := range []struct {
		name     string
		affected []models.AffectedPackage
		want     string
	}{
		{
			name: "ignore unrelated packages and non-semver ranges",
			affected: []models.AffectedPackage{
				{Ranges: []models.AffectedRange{{Type: "SEMVER", Events: []models.RangeEvent{{Introduced: "0"}, {Fixed: "1.0.1"}}}}},
				{Package: &models.VulnerabilityPackage{Ecosystem: "Go", Name: "other"}, Ranges: []models.AffectedRange{{Type: "SEMVER", Events: []models.RangeEvent{{Introduced: "0"}, {Fixed: "1.0.1"}}}}},
				{Package: &models.VulnerabilityPackage{Ecosystem: "npm", Name: packageName}, Ranges: []models.AffectedRange{{Type: "SEMVER", Events: []models.RangeEvent{{Introduced: "0"}, {Fixed: "1.0.1"}}}}},
				{Package: &models.VulnerabilityPackage{Ecosystem: "Go", Name: packageName}, Ranges: []models.AffectedRange{{Type: "GIT", Events: []models.RangeEvent{{Introduced: "0"}, {Fixed: "commit"}}}}},
			},
		},
		{
			name: "select earliest applicable fix across ranges",
			affected: []models.AffectedPackage{{
				Package: &models.VulnerabilityPackage{Ecosystem: "Go", Name: packageName},
				Ranges: []models.AffectedRange{
					{Type: "SEMVER", Events: []models.RangeEvent{{Introduced: "0"}, {Fixed: "1.0.12"}}},
					{Type: "SEMVER", Events: []models.RangeEvent{{Introduced: "v1.0.0"}, {Fixed: "v1.0.9"}}},
				},
			}},
			want: "v1.0.9",
		},
		{
			name: "closed and open-ended intervals have no fix",
			affected: []models.AffectedPackage{{
				Package: &models.VulnerabilityPackage{Ecosystem: "Go", Name: packageName},
				Ranges: []models.AffectedRange{
					{Type: "SEMVER", Events: []models.RangeEvent{{Introduced: "0"}, {LastAffected: "1.0.1"}, {Introduced: "2.0.0"}, {Fixed: "2.0.1"}}},
					{Type: "SEMVER", Events: []models.RangeEvent{{Introduced: "0"}, {Limit: "1.0.1"}, {Introduced: "2.0.0"}, {Fixed: "2.0.1"}}},
					{Type: "SEMVER", Events: []models.RangeEvent{{Introduced: "0"}}},
				},
			}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := fixedversion.Find(tc.affected, packageName, "v1.0.0")
			if err != nil || got != tc.want {
				t.Fatalf("fixed version = %q, err = %v, want %q", got, err, tc.want)
			}
		})
	}
}

func TestFindFixedVersionRejectsInvalidVersions(t *testing.T) {
	for _, tc := range []struct {
		name       string
		installed  string
		introduced string
		fixed      string
	}{
		{"installed", "invalid", "0", "1.0.1"},
		{"introduced", "v1.0.0", "invalid", "1.0.1"},
		{"fixed", "v1.0.0", "0", "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			affected := []models.AffectedPackage{{
				Package: &models.VulnerabilityPackage{Ecosystem: "Go", Name: "example.com/module"},
				Ranges: []models.AffectedRange{{Type: "SEMVER", Events: []models.RangeEvent{
					{Introduced: tc.introduced}, {Fixed: tc.fixed},
				}}},
			}}
			if _, err := fixedversion.Find(affected, "example.com/module", tc.installed); err == nil {
				t.Fatal("expected an invalid-version error")
			}
		})
	}
}
