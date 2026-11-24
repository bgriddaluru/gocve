package gomod

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/bgriddaluru/gocve/pkg/utils/logger"
)

func TestDiscoverModuleLayoutCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := NewClient(logger.NewLogger(false))
	_, err := client.DiscoverModuleLayout(ctx, filepath.Join(t.TempDir(), "missing"), nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation before filesystem access, got %v", err)
	}
}
