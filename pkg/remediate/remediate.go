package remediate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"

	"github.com/bgriddaluru/gocve/pkg/advisory"
	"github.com/bgriddaluru/gocve/pkg/cache"
	"github.com/bgriddaluru/gocve/pkg/gomod"
	"github.com/bgriddaluru/gocve/pkg/models"
	"github.com/bgriddaluru/gocve/pkg/scan"
	"github.com/bgriddaluru/gocve/pkg/utils/logger"
)

type Remediator struct {
	scanner interface {
		ScanModule(context.Context, string) (map[string]*models.PackageVulnerability, error)
	}
	runGo    func(context.Context, *logger.Logger, string, ...string) ([]byte, error)
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
		runGo:    runGoCommand,
		advisory: advisory.NewAdvisory("osv", cache, logger),
		cache:    cache,
		logger:   logger,
		config:   config,
	}
}

func (r *Remediator) Remediate(ctx context.Context) (result models.RemediationResult, err error) {
	result = models.NewRemediationResult()
	defer func() {
		if len(result.Changes) > 0 {
			err = errors.Join(err, r.resolveChanges(ctx, &result))
		}
		result.Completed = err == nil
	}()
	// Detect module layout and gather packages
	moduleClient := gomod.NewClient(r.logger)
	moduleLayout, err := moduleClient.DiscoverModuleLayout(ctx, r.config.Path, r.config.SkipDirs)
	if err != nil {
		r.logger.Error("Failed to discover module layout:", err)
		result.AddError("discover", "", "", err)
		return result, err
	}
	err = r.remediateVulns(ctx, moduleLayout, &result)
	return result, err
}

func (r *Remediator) remediateVulns(ctx context.Context, moduleLayout *models.ModuleLayout, result *models.RemediationResult) error {
	for _, ws := range moduleLayout.Workspaces {
		for _, mod := range ws.Modules {
			updated, err := r.remediateVulnsInModule(ctx, mod.Path, result)
			if err != nil {
				return err
			}

			if updated {
				r.logger.Info("Syncing workspace:", ws.Path)
				if err := r.syncWorkspace(ctx, ws.Path); err != nil {
					result.AddError("workspace_sync", ws.Path, "", err)
					return err
				}
			}
		}
	}

	for _, mod := range moduleLayout.StandaloneModules {
		_, err := r.remediateVulnsInModule(ctx, mod.Path, result)
		if err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		result.AddError("remediate", "", "", err)
		return err
	}
	return nil
}

func (r *Remediator) remediateVulnsInModule(ctx context.Context, modulePath string, result *models.RemediationResult) (bool, error) {
	updated := false
	pkgVulns, err := r.scanner.ScanModule(ctx, modulePath)
	if err != nil {
		result.AddError("scan", modulePath, "", err)
		return false, err
	}
	r.logger.Info("Remediating vulnerabilities in module:", modulePath)
	module := models.NewModuleScanResult(modulePath, pkgVulns)

	for _, vuln := range module.Findings {
		// Skip remediation if there is no fixed version available or severity is unknown
		if vuln.FixedVersion == "" {
			r.logger.Info("Skipping vulnerability:", vuln.VulnerabilityID, "as there is no fixed version available")
			result.Skipped = append(result.Skipped, models.SkippedFinding{
				Module: modulePath, Package: vuln.Package, VulnerabilityID: vuln.VulnerabilityID, Reason: "no_fixed_version",
			})
			continue
		}
		if strings.ToLower(vuln.Severity) == "unknown" {
			r.logger.Info("Skipping vulnerability:", vuln.VulnerabilityID, "as its severity is unknown")
			result.Skipped = append(result.Skipped, models.SkippedFinding{
				Module: modulePath, Package: vuln.Package, VulnerabilityID: vuln.VulnerabilityID, Reason: "unknown_severity",
			})
			continue
		}
		r.logger.Info("Remediating vulnerability:", vuln.VulnerabilityID, "by upgrading package:", vuln.Package, "from:", vuln.InstalledVersion, "to version:", vuln.FixedVersion)
		version := "v" + strings.TrimPrefix(vuln.FixedVersion, "v")
		if err := r.upgradePackage(ctx, modulePath, vuln.Package, version); err != nil {
			result.AddError("upgrade", modulePath, vuln.Package, err)
			return updated, err
		}
		recordChange(result, modulePath, vuln, version)
		updated = true
	}

	if err := r.tidyModule(ctx, modulePath); err != nil {
		result.AddError("tidy", modulePath, "", err)
		return updated, err
	}
	return updated, nil
}

func recordChange(result *models.RemediationResult, module string, finding models.Finding, version string) {
	for i := range result.Changes {
		change := &result.Changes[i]
		if change.Module == module && change.Package == finding.Package {
			change.RequestedVersion = version
			change.VulnerabilityIDs = append(change.VulnerabilityIDs, finding.VulnerabilityID)
			return
		}
	}
	result.Changes = append(result.Changes, models.RemediationChange{
		Module: module, Package: finding.Package, PreviousVersion: finding.InstalledVersion,
		RequestedVersion: version, VulnerabilityIDs: []string{finding.VulnerabilityID},
	})
}

func (r *Remediator) resolveChanges(ctx context.Context, result *models.RemediationResult) error {
	modules := make(map[string][]int)
	var paths []string
	for i, change := range result.Changes {
		if _, ok := modules[change.Module]; !ok {
			paths = append(paths, change.Module)
		}
		modules[change.Module] = append(modules[change.Module], i)
	}
	sort.Strings(paths)
	var errs []error
	for _, path := range paths {
		output, err := r.runGo(ctx, r.logger, path, "list", "-m", "-json", "all")
		versions := make(map[string]string)
		if err == nil {
			decoder := json.NewDecoder(bytes.NewReader(output))
			for {
				var module struct{ Path, Version string }
				if err = decoder.Decode(&module); err != nil {
					if errors.Is(err, io.EOF) {
						err = nil
					}
					break
				}
				if module.Path == "" {
					err = fmt.Errorf("go list returned a module without a path")
					break
				}
				versions[module.Path] = module.Version
			}
			if err == nil && len(versions) == 0 {
				err = fmt.Errorf("go list returned no modules")
			}
		}
		if err != nil {
			err = fmt.Errorf("resolve dependency versions in %q: %w", path, err)
			result.AddError("resolve_versions", path, "", err)
			errs = append(errs, err)
			continue
		}
		for _, i := range modules[path] {
			change := &result.Changes[i]
			version, present := versions[change.Package]
			if !present {
				change.Removed = true
				continue
			}
			if version == "" {
				err := fmt.Errorf("no resolved version for %s in %q", change.Package, path)
				result.AddError("resolve_versions", path, change.Package, err)
				errs = append(errs, err)
				continue
			}
			change.ResolvedVersion = &version
		}
	}
	return errors.Join(errs...)
}

func (r *Remediator) upgradePackage(ctx context.Context, moudulePath, packageName, version string) error {
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	targetPackageURL := fmt.Sprintf("%s@%s", packageName, version)
	// https://github.com/golang/go/issues/58116 - ensure the module is downloaded before running 'go get' to avoid issues with version resolution
	_, err := r.runGo(ctx, r.logger, moudulePath, "mod", "download", targetPackageURL)
	if err != nil {
		return err
	}
	_, err = r.runGo(ctx, r.logger, moudulePath, "get", targetPackageURL)
	return err
}

func (r *Remediator) syncWorkspace(ctx context.Context, workspaceDir string) error {
	_, err := r.runGo(ctx, r.logger, workspaceDir, "work", "sync")
	return err
}

func (r *Remediator) tidyModule(ctx context.Context, modulePath string) error {
	_, err := r.runGo(ctx, r.logger, modulePath, "mod", "tidy")
	return err
}

func runGoCommand(ctx context.Context, logger *logger.Logger, dir string, args ...string) ([]byte, error) {
	if logger != nil {
		logger.Debug("Executing 'go", strings.Join(args, " "), "in", dir)
	}
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go %s in %q: %w\n%s", strings.Join(args, " "), dir, err, strings.TrimSpace(stderr.String()))
	}
	return output, nil
}
