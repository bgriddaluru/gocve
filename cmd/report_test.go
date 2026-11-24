package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bgriddaluru/gocve/pkg/models"
	"github.com/spf13/cobra"
)

func TestCommandJSONReports(t *testing.T) {
	for _, name := range []string{"scan", "remediate"} {
		for _, fail := range []bool{false, true} {
			t.Run(name+map[bool]string{false: "/success", true: "/failure"}[fail], func(t *testing.T) {
				command, _, err := rootCmd.Find([]string{name})
				if err != nil {
					t.Fatal(err)
				}
				command.SetContext(context.Background())
				t.Cleanup(func() {
					command.SetContext(nil)
					if err := command.Flags().Set("json-output", ""); err != nil {
						t.Error(err)
					}
					command.Flags().Lookup("json-output").Changed = false
				})
				root := t.TempDir()
				if fail {
					root = filepath.Join(root, "missing")
				}
				path := filepath.Join(t.TempDir(), "report.json")
				if err := os.WriteFile(path, []byte(`{"stale":true}`), 0600); err != nil {
					t.Fatal(err)
				}
				if err := command.ParseFlags([]string{"--path", root, "--json-output", path}); err != nil {
					t.Fatal(err)
				}
				err = command.RunE(command, nil)
				if (err != nil) != fail {
					t.Fatalf("error = %v, want failure = %v", err, fail)
				}
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var report struct {
					models.Report
					Modules []models.ModuleScanResult  `json:"modules"`
					Changes []models.RemediationChange `json:"changes"`
					Skipped []models.SkippedFinding    `json:"skipped"`
				}
				if err := json.Unmarshal(data, &report); err != nil {
					t.Fatal(err)
				}
				if report.SchemaVersion != 1 || report.Command != name || report.Completed == fail ||
					(len(report.Errors) > 0) != fail {
					t.Fatalf("unexpected report: %s", data)
				}
				if name == "scan" && report.Modules == nil {
					t.Fatalf("modules must be an array: %s", data)
				}
				if name == "remediate" && (report.Changes == nil || report.Skipped == nil) {
					t.Fatalf("changes and skipped must be arrays: %s", data)
				}
			})
		}
	}
}

func reportCommand(t *testing.T, path string) *cobra.Command {
	t.Helper()
	command := &cobra.Command{}
	command.Flags().String("json-output", "", "")
	if err := command.Flags().Set("json-output", path); err != nil {
		t.Fatal(err)
	}
	return command
}

func TestJSONReportPreservesPartialFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte(`{"completed":true,"stale":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("second module failed")
	err := runWithJSONReport(reportCommand(t, path), models.NewScanResult(), func() (models.ScanResult, error) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var initial models.ScanResult
		if err := json.Unmarshal(data, &initial); err != nil || initial.Completed || strings.Contains(string(data), "stale") {
			t.Fatalf("stale report not replaced before execution: %s, %v", data, err)
		}
		result := models.NewScanResult()
		result.Modules = append(result.Modules, models.NewModuleScanResult("first", nil))
		result.AddError("scan", "second", "", failure)
		return result, failure
	})
	if !errors.Is(err, failure) {
		t.Fatalf("lost execution error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var result models.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Completed || len(result.Modules) != 1 || result.Modules[0].Path != "first" ||
		result.Modules[0].Findings == nil || len(result.Errors) != 1 || result.Errors[0].Module != "second" {
		t.Fatalf("unexpected partial result: %s", data)
	}
}

func TestJSONReportRejectsInvalidDestinationBeforeExecution(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{"", " \t", filepath.Join(root, "missing", "report.json"), root} {
		err := runWithJSONReport(reportCommand(t, path), models.NewScanResult(), func() (models.ScanResult, error) {
			t.Fatal("command ran with invalid report destination")
			return models.NewScanResult(), nil
		})
		if err == nil {
			t.Fatalf("accepted destination %q", path)
		}
	}
	files, err := os.ReadDir(root)
	if err != nil || len(files) != 0 {
		t.Fatalf("temporary files were not cleaned: %v, %v", files, err)
	}
}

func TestJSONReportSurfacesFinalWriteFailure(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "report.json")
	failure := errors.New("remediation failed")
	err := runWithJSONReport(reportCommand(t, path), models.NewRemediationResult(), func() (models.RemediationResult, error) {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		return models.NewRemediationResult(), failure
	})
	if !errors.Is(err, failure) || !strings.Contains(err.Error(), "replace JSON report") {
		t.Fatalf("expected execution and report errors: %v", err)
	}
	files, err := filepath.Glob(filepath.Join(root, ".gocve-report-*"))
	if err != nil || len(files) != 0 {
		t.Fatalf("temporary files were not cleaned: %v, %v", files, err)
	}
}
