package gomod

import (
	"os"

	"golang.org/x/mod/modfile"
)

func (g *GoMod) GetModulesFromGoWork(goWorkPath string) ([]string, error) {
	workData, err := g.ParseGoWork(goWorkPath)
	if err != nil {
		return nil, err
	}

	var modules []string
	for _, use := range workData.Use {
		modules = append(modules, use.Path)
	}
	return modules, nil
}

func (g *GoMod) ParseGoWork(goWorkPath string) (*modfile.WorkFile, error) {
	data, err := os.ReadFile(goWorkPath)
	if err != nil {
		return nil, err
	}

	workData, err := modfile.ParseWork("go.work", data, nil)
	if err != nil {
		return nil, err
	}

	return workData, nil
}
