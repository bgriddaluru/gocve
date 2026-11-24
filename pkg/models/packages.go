package models

type Package struct {
	Path     string
	Version  string
	Indirect bool
}

type PackageVulnerabilitySummary struct {
	ID           string
	Severity     string
	FixedVersion string
	Aliases      []string
}

// Wrapper on Vulnerability for group vulns per package version
type PackageVulnerability struct {
	PackageName      string
	InstalledVersion string
	VulnSummary      map[string]*PackageVulnerabilitySummary
}
