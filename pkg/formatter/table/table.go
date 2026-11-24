package table

import (
	"github.com/bgriddaluru/gocve/pkg/models"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

func PrintPackageVulnerabilities(pkgVulns map[string]*models.PackageVulnerability) {
	t := table.NewWriter()
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: true},
		{Number: 2, AutoMerge: true},
		{Number: 3, AutoMerge: true},
		{Number: 4, AutoMerge: true},
		{Number: 5, AutoMerge: true},
	})

	style := table.StyleDefault
	style.Color.Header = text.Colors{text.FgHiCyan, text.Bold}
	style.Color.Row = text.Colors{text.FgWhite}
	style.Color.RowAlternate = style.Color.Row
	style.Box = table.StyleBoxRounded
	style.Options.SeparateRows = true
	t.SetStyle(style)

	t.AppendHeader(table.Row{"CVE", "Severity", "Package", "Installed", "Fixed"})
	for _, p := range pkgVulns {
		for vulnID, vulnSummary := range p.VulnSummary {
			t.AppendRow(table.Row{vulnID, vulnSummary.Severity, p.PackageName, p.InstalledVersion, vulnSummary.FixedVersion})
		}

	}
	print(t.Render())
	println()
}
