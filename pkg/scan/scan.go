package scan

import (
	"context"
	"fmt"
	"strings"

	"github.com/bgriddaluru/gocve/pkg/advisory"
	"github.com/bgriddaluru/gocve/pkg/cache"
	"github.com/bgriddaluru/gocve/pkg/formatter/table"
	"github.com/bgriddaluru/gocve/pkg/gomod"
	"github.com/bgriddaluru/gocve/pkg/models"
	"github.com/bgriddaluru/gocve/pkg/utils/logger"
)

type Scanner struct {
	advisory *advisory.Advisory
	cache    *cache.Cache
	logger   *logger.Logger
	config   models.Config
}

func NewScanner(config models.Config) *Scanner {
	cache := cache.NewCache()
	logger := logger.NewLogger(config.Debug)
	return &Scanner{
		advisory: advisory.NewAdvisory("osv", cache, logger),
		cache:    cache,
		logger:   logger,
		config:   config,
	}
}

func (s *Scanner) Scan(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Detect module layout and gather packages
	moduleClient := gomod.NewClient(s.logger)
	moduleLayout, err := moduleClient.DiscoverModuleLayout(ctx, s.config.Path, s.config.SkipDirs)
	if err != nil {
		s.logger.Error("Failed to discover module layout:", err)
		return err
	}

	// Workspace modules
	for _, ws := range moduleLayout.Workspaces {
		s.logger.Debug("Workspace:", ws.Path)
		s.logger.Debug("====================================")
		for _, mod := range ws.Modules {
			if err := ctx.Err(); err != nil {
				return err
			}
			_, err := s.ScanModule(ctx, mod.Path)
			if err != nil {
				return err
			}
		}
	}

	for _, mod := range moduleLayout.StandaloneModules {
		if err := ctx.Err(); err != nil {
			return err
		}
		s.logger.Debug("Standalone Module:", mod.Path)
		s.logger.Debug("====================================")
		_, err := s.ScanModule(ctx, mod.Path)
		if err != nil {
			return err
		}

	}

	return ctx.Err()
}

func (s *Scanner) ScanModule(ctx context.Context, modulePath string) (map[string]*models.PackageVulnerability, error) {
	s.logger.Info("Scanning Module for vulnerabilities:", modulePath)
	moduleClient := gomod.NewClient(s.logger)
	packages, err := moduleClient.GetPackages(modulePath)
	if err != nil {
		s.logger.Error("Failed to get packages for module:", modulePath, err)
		return nil, err
	}
	// Query vulnerabilities for the packages
	vulns, err := s.advisory.QueryVulnerabilities(ctx, packages)
	if err != nil {
		return nil, fmt.Errorf("query vulnerabilities for module %s: %w", modulePath, err)
	}
	s.filterVulnerabilities(vulns)
	if len(vulns) != 0 {
		table.PrintPackageVulnerabilities(vulns)
	} else {
		s.logger.Info("\t No vulnerabilities found in module:", modulePath)
	}
	s.logger.Debug("-----------------------------")
	return vulns, nil
}

func (s *Scanner) filterVulnerabilities(vulns map[string]*models.PackageVulnerability) {
	if !s.config.IgnoreUnfixed && !s.config.IgnoreUnknownSeverity {
		return
	}
	for packageID, pkg := range vulns {
		for vulnID, summary := range pkg.VulnSummary {
			if (s.config.IgnoreUnfixed && summary.FixedVersion == "") ||
				(s.config.IgnoreUnknownSeverity && (summary.Severity == "" || strings.EqualFold(summary.Severity, "UNKNOWN"))) {
				delete(pkg.VulnSummary, vulnID)
			}
		}
		if len(pkg.VulnSummary) == 0 {
			delete(vulns, packageID)
		}
	}
}
