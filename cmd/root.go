/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"os"
	"os/signal"

	"github.com/bgriddaluru/gocve/pkg/models"
	"github.com/bgriddaluru/gocve/pkg/remediate"
	"github.com/bgriddaluru/gocve/pkg/scan"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gocve",
	Short: "Scan and remediate vulnerabilities in Go repositories",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := rootCmd.ExecuteContext(ctx)
	stop()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan vulnerabilities in Go repositories",
		Args:  cobra.NoArgs,
		RunE:  runScan,
	}

	remediateCmd := &cobra.Command{
		Use:   "remediate",
		Short: "Remediate vulnerabilities in Go repositories",
		Args:  cobra.NoArgs,
		RunE:  runRemediation,
	}
	for _, subcommand := range []*cobra.Command{scanCmd, remediateCmd} {
		subcommand.Flags().String("path", ".", "Path to the Go repository")
		subcommand.Flags().StringSlice("skip-dirs", nil, "Directory names to skip (comma-separated or repeated)")
		subcommand.Flags().Bool("debug", false, "Enable debug logging")
		rootCmd.AddCommand(subcommand)
		subcommand.Flags().Bool("ignore-unfixed", false, "Exclude vulnerabilities without a known fixed version")
		subcommand.Flags().Bool("ignore-unknown-severity", false, "Exclude vulnerabilities with unknown severity")
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	config, err := buildConfig(cmd)
	if err != nil {
		return err
	}

	scanner := scan.NewScanner(config)
	return scanner.Scan(cmd.Context())
}

func runRemediation(cmd *cobra.Command, args []string) error {
	config, err := buildConfig(cmd)
	if err != nil {
		return err
	}

	remediator := remediate.NewRemediator(config)
	return remediator.Remediate(cmd.Context())
}

func buildConfig(cmd *cobra.Command) (models.Config, error) {
	path, err := cmd.Flags().GetString("path")
	if err != nil {
		return models.Config{}, err
	}
	skipDirs, err := cmd.Flags().GetStringSlice("skip-dirs")
	if err != nil {
		return models.Config{}, err
	}
	debug, err := cmd.Flags().GetBool("debug")
	if err != nil {
		return models.Config{}, err
	}
	ignoreUnfixed, err := cmd.Flags().GetBool("ignore-unfixed")
	if err != nil {
		return models.Config{}, err
	}
	ignoreUnknownSeverity, err := cmd.Flags().GetBool("ignore-unknown-severity")
	if err != nil {
		return models.Config{}, err
	}
	return models.Config{
		Path:                  path,
		SkipDirs:              skipDirs,
		Debug:                 debug,
		IgnoreUnfixed:         ignoreUnfixed,
		IgnoreUnknownSeverity: ignoreUnknownSeverity,
	}, nil
}
