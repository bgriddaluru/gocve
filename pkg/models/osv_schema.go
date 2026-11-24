package models

import (
	"encoding/json"
	"time"
)

// Reference:https://ossf.github.io/osv-schema/

// OSV represents an Open Source Vulnerability record returned by GET /v1/vulns/{id}.
// See https://ossf.github.io/osv-schema/ for field semantics and validation rules.
type OSV struct {
	SchemaVersion    string                     `json:"schema_version,omitempty"`
	ID               string                     `json:"id"`
	Modified         time.Time                  `json:"modified"`
	Published        *time.Time                 `json:"published,omitempty"`
	Withdrawn        *time.Time                 `json:"withdrawn,omitempty"`
	Aliases          []string                   `json:"aliases,omitempty"`
	Upstream         []string                   `json:"upstream,omitempty"`
	Related          []string                   `json:"related,omitempty"`
	Summary          string                     `json:"summary,omitempty"`
	Details          string                     `json:"details,omitempty"`
	Severity         []Severity                 `json:"severity,omitempty"`
	Affected         []AffectedPackage          `json:"affected,omitempty"`
	References       []Reference                `json:"references,omitempty"`
	Credits          []Credit                   `json:"credits,omitempty"`
	DatabaseSpecific map[string]json.RawMessage `json:"database_specific,omitempty"`
}

type Severity struct {
	Type   string `json:"type"`
	Score  string `json:"score"`
	Source string `json:"source,omitempty"`
}

type AffectedPackage struct {
	Package           *VulnerabilityPackage      `json:"package,omitempty"`
	Severity          []Severity                 `json:"severity,omitempty"`
	Ranges            []AffectedRange            `json:"ranges,omitempty"`
	Versions          []string                   `json:"versions,omitempty"`
	EcosystemSpecific map[string]json.RawMessage `json:"ecosystem_specific,omitempty"`
	DatabaseSpecific  map[string]json.RawMessage `json:"database_specific,omitempty"`
}

// VulnerabilityPackage is the OSV package identity, separate from a dependency's version.
type VulnerabilityPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl,omitempty"`
}

type AffectedRange struct {
	Type             string                     `json:"type"`
	Repo             string                     `json:"repo,omitempty"`
	Events           []RangeEvent               `json:"events"`
	DatabaseSpecific map[string]json.RawMessage `json:"database_specific,omitempty"`
}

// RangeEvent contains one boundary: introduced, fixed, last_affected, or limit.
type RangeEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type Credit struct {
	Name    string   `json:"name"`
	Contact []string `json:"contact,omitempty"`
	Type    string   `json:"type,omitempty"`
}
