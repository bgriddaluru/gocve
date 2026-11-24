package models

type Config struct {
	// Path to the Go repository
	Path string
	// Directory names to skip (comma-separated or repeated)
	SkipDirs []string
	// Enable debug logging
	Debug bool
	// Exclude scan findings without a known fixed version.
	IgnoreUnfixed bool
	// Exclude scan findings with unknown severity.
	IgnoreUnknownSeverity bool
}
