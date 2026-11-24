package advisory

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/bgriddaluru/gocve/pkg/advisory/provider/osvdev"
	"github.com/bgriddaluru/gocve/pkg/cache"
	"github.com/bgriddaluru/gocve/pkg/models"
	"github.com/bgriddaluru/gocve/pkg/osvutils/fixedversion"
	"github.com/bgriddaluru/gocve/pkg/osvutils/severity"
	"github.com/bgriddaluru/gocve/pkg/utils/logger"
)

type Provider interface {
	QueryPackageVulnerabilities(ctx context.Context, packages []models.Package) (map[string]*models.PackageVulnerability, error)
	GetVulnerability(ctx context.Context, vulnId string) (models.OSV, error)
}

type Advisory struct {
	provider Provider
	cache    *cache.Cache
	logger   *logger.Logger
}

func NewAdvisory(providerName string, cache *cache.Cache, logger *logger.Logger) *Advisory {
	var provider Provider
	switch providerName {
	case "osv":
		fallthrough
	default:
		provider = osvdev.NewClient(logger, cache)
	}
	return &Advisory{
		provider: provider,
		cache:    cache,
		logger:   logger,
	}
}

func (a *Advisory) QueryVulnerabilities(ctx context.Context, packages []models.Package) (map[string]*models.PackageVulnerability, error) {
	// Base query for vulnerabilities
	pkgVulns, err := a.provider.QueryPackageVulnerabilities(ctx, packages)
	if err != nil {
		return nil, err
	}

	a.printPackageVulnerabilities(pkgVulns)

	err = a.EnrichWithVulnerabilityAliases(ctx, pkgVulns)
	if err != nil {
		return nil, err
	}

	a.printPackageVulnerabilities(pkgVulns)

	err = a.EnrichWithFixedVersionAndSeverity(ctx, pkgVulns)
	if err != nil {
		return nil, err
	}
	return pkgVulns, err
}

// EnrichWithVulnerabilityAliases merges equivalent findings per package version, preferring CVE IDs over Go and GHSA IDs.
func (a *Advisory) EnrichWithVulnerabilityAliases(ctx context.Context, pkgVulns map[string]*models.PackageVulnerability) error {
	// Add aliases for each vulnerability
	for _, pkg := range pkgVulns {
		for vulnID, vulnSummary := range pkg.VulnSummary {
			vulnDetail, err := a.provider.GetVulnerability(ctx, vulnID)
			if err != nil {
				return fmt.Errorf("get vulnerability from cache: %w", err)
			}
			aliases := vulnDetail.Aliases
			if len(aliases) != 0 {
				vulnSummary.Aliases = append(vulnSummary.Aliases, aliases...)
			}
		}
		pkg.VulnSummary = deduplicateVulnerabilities(pkg.VulnSummary)
	}

	return nil
}

func deduplicateVulnerabilities(summaries map[string]*models.PackageVulnerabilitySummary) map[string]*models.PackageVulnerabilitySummary {
	neighbors := make(map[string][]string)
	ids := make([]string, 0, len(summaries))
	for id, summary := range summaries {
		ids = append(ids, id)
		neighbors[id] = append(neighbors[id], summary.Aliases...)
		for _, alias := range summary.Aliases {
			neighbors[alias] = append(neighbors[alias], id)
		}
	}

	priority := func(id string) int {
		for rank, prefix := range []string{"CVE-", "GO-", "GHSA-"} {
			if strings.HasPrefix(id, prefix) {
				return rank
			}
		}
		return 3
	}
	sort.Strings(ids)

	merged := make(map[string]*models.PackageVulnerabilitySummary, len(summaries))
	visited := make(map[string]bool)
	// Walking the alias graph also merges findings connected through a shared or transitive alias.
	for _, id := range ids {
		if visited[id] {
			continue
		}
		var aliases []string
		pending := []string{id}
		visited[id] = true
		for len(pending) > 0 {
			current := pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			aliases = append(aliases, current)
			for _, alias := range neighbors[current] {
				if !visited[alias] {
					visited[alias] = true
					pending = append(pending, alias)
				}
			}
		}
		sort.Strings(aliases)
		primaryID := aliases[0]
		for _, alias := range aliases[1:] {
			if priority(alias) < priority(primaryID) {
				primaryID = alias
			}
		}
		summary := summaries[id]
		summary.ID = primaryID
		summary.Aliases = aliases
		merged[primaryID] = summary
	}
	return merged
}

// TODO: Handle when multiple CVEs are associated with single GO vulnerability
// TODO: Handle when same package have multiple vulnerabilities
func (a *Advisory) EnrichWithFixedVersionAndSeverity(ctx context.Context, pkgVulns map[string]*models.PackageVulnerability) error {
	// Enrich package summary details
	for _, pkg := range pkgVulns {
		for vulnID, vulnSummary := range pkg.VulnSummary {
			goVulnID, cveVulnID := findVulnerabilityIDs(vulnID, vulnSummary.Aliases)

			cveVulnDetail, err := a.provider.GetVulnerability(ctx, cveVulnID)
			if err != nil {
				return fmt.Errorf("get vulnerability from cache: %w", err)
			}
			goVulnDetail, err := a.provider.GetVulnerability(ctx, goVulnID)
			if err != nil {
				return fmt.Errorf("get vulnerability from cache: %w", err)
			}

			// Find fixed version from Go vulnerability details
			fixedVersion, err := fixedversion.Find(goVulnDetail.Affected, pkg.PackageName, pkg.InstalledVersion)
			if err != nil {
				return fmt.Errorf("find fixed version for %s@%s: %w", pkg.PackageName, pkg.InstalledVersion, err)
			}

			// Caluclate severity for the vulnerability
			severityStr, err := severity.CalculateSeverity(cveVulnDetail.Severity)
			if err != nil {
				return fmt.Errorf("calculate severity score: %w", err)
			}

			vulnSummary.FixedVersion = fixedVersion
			vulnSummary.Severity = severityStr
		}
	}
	return nil
}

func findVulnerabilityIDs(vulnID string, aliases []string) (goID, cveID string) {
	for _, id := range append([]string{vulnID}, aliases...) {
		if cveID == "" && strings.HasPrefix(id, "CVE-") {
			cveID = id
		} else if goID == "" && strings.HasPrefix(id, "GO-") {
			goID = id
		}
		if goID != "" && cveID != "" {
			break
		}
	}
	return goID, cveID
}

func (a *Advisory) printPackageVulnerabilities(pkgVulns map[string]*models.PackageVulnerability) {
	for _, p := range pkgVulns {
		for vulnID, vulnSummary := range p.VulnSummary {
			a.logger.Debug("CVE:", vulnID, "Severity:", vulnSummary.Severity, "Package:", p.PackageName, "Installed:", p.InstalledVersion, "Fixed:", vulnSummary.FixedVersion, "Aliases:", vulnSummary.Aliases)
		}
	}
	a.logger.Debug("-----------------------------")
}
