package version

import (
	"fmt"
	"runtime"
)

var (
	// Version is the current version of the application
	Version = "dev"
	// Commit is the git commit SHA at build time
	Commit = "none"
	// Date is the build date
	Date = "unknown"
)

// BuildInfo returns a string with version information
func BuildInfo() string {
	return fmt.Sprintf(
		"Waffle %s (commit: %s, built at: %s, using: %s)",
		Version,
		Commit,
		Date,
		runtime.Version(),
	)
}

// GetVersion returns the current version
func GetVersion() string {
	return Version
}

// GetCommit returns the git commit SHA
func GetCommit() string {
	return Commit
}

// GetDate returns the build date
func GetDate() string {
	return Date
}
