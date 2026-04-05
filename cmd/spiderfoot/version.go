package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Build-time variables set via ldflags.
var (
	// Version is the application version.
	Version = "dev"
	// Commit is the git commit hash.
	Commit = "none"
	// Date is the build date.
	Date = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Printf("spiderfoot version %s (commit: %s, built: %s)\n", Version, Commit, Date)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
