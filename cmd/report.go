package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func runWithJSONReport[T any](cmd *cobra.Command, initial T, run func() (T, error)) error {
	path, err := cmd.Flags().GetString("json-output")
	if err != nil {
		return err
	}
	if path == "" && !cmd.Flags().Changed("json-output") {
		_, err := run()
		return err
	}
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("--json-output requires a nonempty file path")
	}
	// Replace stale results and validate the destination before any remediation.
	if err := writeJSONReport(path, initial); err != nil {
		return err
	}
	result, runErr := run()
	return errors.Join(runErr, writeJSONReport(path, result))
}

func writeJSONReport(path string, result any) (err error) {
	file, err := os.CreateTemp(filepath.Dir(path), ".gocve-report-*")
	if err != nil {
		return fmt.Errorf("create JSON report %q: %w", path, err)
	}
	defer func() {
		if cleanupErr := os.Remove(file.Name()); cleanupErr != nil && !errors.Is(cleanupErr, os.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("remove temporary JSON report: %w", cleanupErr))
		}
	}()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(result)
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return fmt.Errorf("write JSON report %q: %w", path, err)
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return fmt.Errorf("replace JSON report %q: %w", path, err)
	}
	return nil
}
