package remediate

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/bgriddaluru/gocve/pkg/advisory"
	"github.com/bgriddaluru/gocve/pkg/cache"
	"github.com/bgriddaluru/gocve/pkg/gomod"
	"github.com/bgriddaluru/gocve/pkg/models"
	"github.com/bgriddaluru/gocve/pkg/scan"
	"github.com/bgriddaluru/gocve/pkg/utils/logger"
)

type Remediator struct {
	scanner  *scan.Scanner
	advisory *advisory.Advisory
	cache    *cache.Cache
	logger   *logger.Logger
	config   models.Config
}

func NewRemediator(config models.Config) *Remediator {
	cache := cache.NewCache()
	logger := logger.NewLogger(config.Debug)
	return &Remediator{
		scanner:  scan.NewScanner(config),
		advisory: advisory.NewAdvisory("osv", cache, logger),
		cache:    cache,
		logger:   logger,
		config:   config,
	}
}

func (r *Remediator) Remediate(ctx context.Context) error {
	// Detect module layout and gather packages
	moduleClient := gomod.NewClient(r.logger)
	moduleLayout, err := moduleClient.DiscoverModuleLayout(ctx, r.config.Path, r.config.SkipDirs)
	if err != nil {
		r.logger.Error("Failed to discover module layout:", err)
		return err
	}
	if err := r.remediateVulns(ctx, moduleLayout); err != nil {
		return err
	}
	return nil
}

func (r *Remediator) remediateVulns(ctx context.Context, moduleLayout *models.ModuleLayout) error {
	for _, ws := range moduleLayout.Workspaces {
		for _, mod := range ws.Modules {
			updated, err := r.remediateVulnsInModule(ctx, mod.Path)
			if err != nil {
				return err
			}
			if updated {

				r.logger.Info("Syncing workspace:", ws.Path)
				if err := r.syncWorkspace(ctx, ws.Path); err != nil {
					return err
				}
			}
		}
	}

	for _, mod := range moduleLayout.StandaloneModules {
		_, err := r.remediateVulnsInModule(ctx, mod.Path)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *Remediator) remediateVulnsInModule(ctx context.Context, modulePath string) (bool, error) {
	updated := false
	pkgVulns, err := r.scanner.ScanModule(ctx, modulePath)
	if err != nil {
		return false, err
	}
	r.logger.Info("Remediating vulnerabilities in module:", modulePath)
	for _, pkgVuln := range pkgVulns {
		for _, vuln := range pkgVuln.VulnSummary {
			// Skip remediation if there is no fixed version available or severity is unknown
			if vuln.FixedVersion == "" {
				r.logger.Info("Skipping vulnerability:", vuln.ID, "as there is no fixed version available")
				continue
			}
			if strings.ToLower(vuln.Severity) == "unknown" {
				r.logger.Info("Skipping vulnerability:", vuln.ID, "as its severity is unknown")
				continue
			}
			r.logger.Info("Remediating vulnerability:", vuln.ID, "by upgrading package:", pkgVuln.PackageName, "from:", pkgVuln.InstalledVersion, "to version:", vuln.FixedVersion)
			if err := r.upgradePackage(ctx, modulePath, pkgVuln.PackageName, vuln.FixedVersion); err != nil {
				return updated, err
			}
			updated = true
		}
	}

	if updated {
		if err := r.tidyModule(ctx, modulePath); err != nil {
			return updated, err
		}
	}
	return updated, nil
}

func (r *Remediator) upgradePackage(ctx context.Context, workspaceDir, packageName, version string) error {
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	cmd := exec.CommandContext(ctx, "go", "get", fmt.Sprintf("%s@%s", packageName, version))
	cmd.Dir = workspaceDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go get %s@%s in %q: %w\n%s",
			packageName, version, workspaceDir, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (r *Remediator) syncWorkspace(ctx context.Context, workspaceDir string) error {
	cmd := exec.CommandContext(ctx, "go", "work", "sync")
	cmd.Dir = workspaceDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go work sync in %q: %w\n%s",
			workspaceDir, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (r *Remediator) tidyModule(ctx context.Context, workspaceDir string) error {
	cmd := exec.CommandContext(ctx, "go", "mod", "tidy")
	cmd.Dir = workspaceDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go mod tidy in %q: %w\n%s",
			workspaceDir, err, strings.TrimSpace(string(output)))
	}
	return nil
}
