package models

import "sort"

type Report struct {
	SchemaVersion int           `json:"schema_version"`
	Command       string        `json:"command"`
	Completed     bool          `json:"completed"`
	Errors        []ReportError `json:"errors"`
}

type ReportError struct {
	Stage   string `json:"stage"`
	Module  string `json:"module,omitempty"`
	Package string `json:"package,omitempty"`
	Message string `json:"message"`
}

func NewReport(command string) Report {
	return Report{SchemaVersion: 1, Command: command, Errors: []ReportError{}}
}

func (r *Report) AddError(stage, module, pkg string, err error) {
	r.Errors = append(r.Errors, ReportError{Stage: stage, Module: module, Package: pkg, Message: err.Error()})
}

type ScanResult struct {
	Report
	Modules []ModuleScanResult `json:"modules"`
}

type ModuleScanResult struct {
	Path     string    `json:"path"`
	Findings []Finding `json:"findings"`
}

type Finding struct {
	Package          string   `json:"package"`
	InstalledVersion string   `json:"installed_version"`
	VulnerabilityID  string   `json:"vulnerability_id"`
	Severity         string   `json:"severity"`
	FixedVersion     string   `json:"fixed_version"`
	Aliases          []string `json:"aliases"`
}

func NewScanResult() ScanResult {
	return ScanResult{Report: NewReport("scan"), Modules: []ModuleScanResult{}}
}

func NewModuleScanResult(path string, vulns map[string]*PackageVulnerability) ModuleScanResult {
	result := ModuleScanResult{Path: path, Findings: []Finding{}}
	for _, pkg := range vulns {
		for id, summary := range pkg.VulnSummary {
			aliases := append([]string{}, summary.Aliases...)
			sort.Strings(aliases)
			result.Findings = append(result.Findings, Finding{
				Package: pkg.PackageName, InstalledVersion: pkg.InstalledVersion,
				VulnerabilityID: id, Severity: summary.Severity,
				FixedVersion: summary.FixedVersion, Aliases: aliases,
			})
		}
	}
	sort.Slice(result.Findings, func(i, j int) bool {
		a, b := result.Findings[i], result.Findings[j]
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		if a.InstalledVersion != b.InstalledVersion {
			return a.InstalledVersion < b.InstalledVersion
		}
		return a.VulnerabilityID < b.VulnerabilityID
	})
	return result
}

type RemediationResult struct {
	Report
	Changes []RemediationChange `json:"changes"`
	Skipped []SkippedFinding    `json:"skipped"`
}

type RemediationChange struct {
	Module           string   `json:"module"`
	Package          string   `json:"package"`
	PreviousVersion  string   `json:"previous_version"`
	RequestedVersion string   `json:"requested_version"`
	ResolvedVersion  *string  `json:"resolved_version"`
	Removed          bool     `json:"removed"`
	VulnerabilityIDs []string `json:"vulnerability_ids"`
}

type SkippedFinding struct {
	Module          string `json:"module"`
	Package         string `json:"package"`
	VulnerabilityID string `json:"vulnerability_id"`
	Reason          string `json:"reason"`
}

func NewRemediationResult() RemediationResult {
	return RemediationResult{
		Report: NewReport("remediate"), Changes: []RemediationChange{}, Skipped: []SkippedFinding{},
	}
}
