package gomod

import (
	"os"
	"path/filepath"

	"github.com/bgriddaluru/gocve/pkg/models"

	"golang.org/x/mod/modfile"
)

func (g *GoMod) GetPackages(modulePath string) ([]models.Package, error) {
	data, err := os.ReadFile(filepath.Join(modulePath, "go.mod"))
	if err != nil {
		return nil, err
	}

	modData, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return nil, err
	}

	packageMap := make(map[string]models.Package)
	for _, req := range modData.Require {
		packageMap[req.Mod.Path] = models.Package{
			Path:     req.Mod.Path,
			Version:  req.Mod.Version,
			Indirect: req.Indirect,
		}
	}

	for _, rep := range modData.Replace {
		if rep.Old.Version != "" {
			dep := packageMap[rep.Old.Path]
			dep.Version = rep.New.Version
			packageMap[rep.Old.Path] = dep
		}
	}

	packages := make([]models.Package, 0, len(packageMap))
	for _, pkg := range packageMap {
		packages = append(packages, pkg)
	}
	return packages, nil
}
