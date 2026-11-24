package models

type ModuleInfo struct {
	Path string
}

type WorkspaceInfo struct {
	Path    string
	Modules []ModuleInfo
}

type ModuleLayout struct {
	Workspaces        []WorkspaceInfo
	StandaloneModules []ModuleInfo
}

func (g *ModuleLayout) InitializeWorkspaces(wsDirs []string) {
	for _, wsDir := range wsDirs {
		g.Workspaces = append(g.Workspaces, WorkspaceInfo{
			Path:    wsDir,
			Modules: []ModuleInfo{},
		})
	}
}

func (g *ModuleLayout) AddModuleToNonWorkspace(path string) {
	g.StandaloneModules = append(g.StandaloneModules, ModuleInfo{
		Path: path,
	})
}

func (g *ModuleLayout) AddModuleToWorkspace(path string, wsName string) {
	for i, workspace := range g.Workspaces {
		if workspace.Path == wsName {
			g.Workspaces[i].Modules = append(g.Workspaces[i].Modules, ModuleInfo{
				Path: path,
			})
			break
		}
	}
}
