package gomod

import (
	"context"
	"os"
	"path/filepath"

	"github.com/bgriddaluru/gocve/pkg/models"
)

func (g *GoMod) DiscoverModuleLayout(ctx context.Context, root string, excludeDirs []string) (*models.ModuleLayout, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Check if the root path exists
	if _, err := os.Stat(root); err != nil {
		g.logger.Error("Error: ", root, " path does not exist")
		return nil, err
	}

	excludeDirsMap := make(map[string]struct{})
	for _, excludeDir := range excludeDirs {
		excludeDirsMap[excludeDir] = struct{}{}
	}

	var moduleDirs []string
	var workspaceDirs []string
	modulesToWorkspaceMap := make(map[string]string)

	// WalkDir() is more efficient than Walk() because it avoids calling os.Stat on every file
	// Walks all the files including subdirectories and their file entries
	err := filepath.WalkDir(root,
		func(path string, dirEntry os.DirEntry, err error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err != nil {
				return nil
			}
			if dirEntry.IsDir() {
				if _, ok := excludeDirsMap[dirEntry.Name()]; ok {
					return filepath.SkipDir
				}
				return nil
			}
			dirName := filepath.Dir(path)
			switch dirEntry.Name() {
			case "go.mod":
				moduleDirs = append(moduleDirs, dirName)
			case "go.work":
				// Extract modules from go.work file
				wsModules, err := g.GetModulesFromGoWork(path)
				if err != nil {
					g.logger.Error("Error: ", path, " failed to parse go.work")
					return err
				}
				// Convert the relative module paths to absolute paths based on the go.work file location
				for _, wsModulePath := range wsModules {
					absPath := filepath.Join(filepath.Dir(path), wsModulePath)
					modulesToWorkspaceMap[absPath] = dirName // Map module -> workspace
				}
				workspaceDirs = append(workspaceDirs, dirName)
			}
			return nil
		})
	if err != nil {
		return nil, err
	}

	moduleLayout := models.ModuleLayout{}

	// Initialize workspaces in moduleLayout based on workspaceDirs
	moduleLayout.InitializeWorkspaces(workspaceDirs)

	for _, moduleDir := range moduleDirs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		workspaceName := modulesToWorkspaceMap[moduleDir]
		g.logger.Debug("Processing module: ", moduleDir, " workspace: "+workspaceName)
		if workspaceName == "" {
			moduleLayout.AddModuleToNonWorkspace(moduleDir)
		} else {
			moduleLayout.AddModuleToWorkspace(moduleDir, workspaceName)
		}
	}

	return &moduleLayout, nil
}
