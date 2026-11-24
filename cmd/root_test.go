package cmd

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestSubcommandFlags(t *testing.T) {
	for _, name := range []string{"scan", "remediate"} {
		t.Run(name, func(t *testing.T) {
			cmd, _, err := rootCmd.Find([]string{name})
			if err != nil {
				t.Fatal(err)
			}
			if cmd == rootCmd {
				t.Fatalf("subcommand %q not registered", name)
			}
			if err := cmd.ParseFlags([]string{"--skip-dirs=vendor,.git", "--skip-dirs=node_modules", "--debug"}); err != nil {
				t.Fatal(err)
			}
			dirs, err := cmd.Flags().GetStringSlice("skip-dirs")
			if err != nil {
				t.Fatal(err)
			}
			if want := []string{"vendor", ".git", "node_modules"}; !reflect.DeepEqual(dirs, want) {
				t.Fatalf("skip-dirs = %v, want %v", dirs, want)
			}
			debug, err := cmd.Flags().GetBool("debug")
			if err != nil {
				t.Fatal(err)
			}
			if !debug {
				t.Fatal("debug flag was not enabled")
			}
			if err := cmd.Args(cmd, []string{"unexpected"}); err == nil {
				t.Fatal("unexpected positional argument was accepted")
			}
			rootCmd.SetArgs([]string{name, "--path", t.TempDir(), "--debug=false"})
			err = rootCmd.ExecuteContext(context.Background())
			if err != nil {
				t.Fatalf("%s of empty directory failed: %v", name, err)
			}

		})
	}
}

func TestSubcommandCancellation(t *testing.T) {
	for _, name := range []string{"scan", "remediate"} {
		t.Run(name, func(t *testing.T) {
			cmd, _, err := rootCmd.Find([]string{name})
			if err != nil {
				t.Fatal(err)
			}
			cmd.SetContext(nil)
			t.Cleanup(func() {
				cmd.SetContext(nil)
				rootCmd.SetContext(nil)
			})
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			rootCmd.SetArgs([]string{name, "--path", t.TempDir()})
			if err := rootCmd.ExecuteContext(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("expected cancellation from %s, got %v", name, err)
			}
		})
	}
}

func TestSubcommandIgnoreFlags(t *testing.T) {
	scanCmd, _, err := rootCmd.Find([]string{"scan"})
	if err != nil {
		t.Fatal(err)
	}
	remediateCmd, _, err := rootCmd.Find([]string{"remediate"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ignore-unfixed", "ignore-unknown-severity"} {
		flag := scanCmd.Flags().Lookup(name)
		if flag == nil {
			t.Fatalf("scan flag %q not registered", name)
		}
		if flag.DefValue != "false" {
			t.Fatalf("%s default = %q, want false", name, flag.DefValue)
		}
		remediateFlag := remediateCmd.Flags().Lookup(name)
		if remediateFlag == nil || remediateFlag.DefValue != "false" {
			t.Fatalf("remediate flag %q missing or has incorrect default", name)
		}
		t.Cleanup(func() {
			if err := scanCmd.Flags().Set(name, "false"); err != nil {
				t.Error(err)
			}
		})
	}
	scanCmd.SetContext(context.Background())
	t.Cleanup(func() { scanCmd.SetContext(nil) })
	if err := scanCmd.ParseFlags([]string{"--path", t.TempDir(), "--ignore-unfixed", "--ignore-unknown-severity"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ignore-unfixed", "ignore-unknown-severity"} {
		enabled, err := scanCmd.Flags().GetBool(name)
		if err != nil || !enabled {
			t.Fatalf("%s = %v, error = %v", name, enabled, err)
		}
	}
	if err := runScan(scanCmd, nil); err != nil {
		t.Fatalf("scan with ignore flags failed: %v", err)
	}
}
