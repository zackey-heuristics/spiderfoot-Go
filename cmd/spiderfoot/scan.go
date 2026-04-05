package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/db"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	_ "github.com/zackey-heuristics/spiderfoot-Go/internal/modules"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/scan"
)

var (
	scanTarget  string
	scanModules string
	scanOutput  string
	scanDB      string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run a scan from the command line",
	RunE: func(_ *cobra.Command, _ []string) error {
		if scanTarget == "" {
			return fmt.Errorf("--target is required")
		}

		dbPath := ":memory:"
		if scanDB != "" {
			dbPath = scanDB
		}
		database, err := db.Open(dbPath)
		if err != nil {
			return fmt.Errorf("open database: %w", err)
		}
		defer database.Close()

		scanID := uuid.New().String()
		if err := database.ScanCreate(scanID, "cli-scan", scanTarget); err != nil {
			return fmt.Errorf("create scan: %w", err)
		}

		mods := strings.Split(scanModules, ",")
		// Always include stor_db for persistence.
		hasStor := false
		for _, m := range mods {
			if strings.TrimSpace(m) == "stor_db" {
				hasStor = true
				break
			}
		}
		if !hasStor {
			mods = append([]string{"stor_db"}, mods...)
		}

		bus := event.NewBus()
		s := scan.New(database, bus, cfg, scanID, scanTarget, mods)

		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		if err := s.Start(ctx); err != nil {
			if errors.Is(err, scan.ErrScanAborted) {
				fmt.Fprintln(os.Stderr, "scan aborted")
			} else {
				return fmt.Errorf("scan failed: %w", err)
			}
		}

		// Collect results.
		events, err := database.EventsGet(scanID, "")
		if err != nil {
			return fmt.Errorf("get results: %w", err)
		}

		out := os.Stdout
		if scanOutput != "" {
			f, err := os.Create(scanOutput)
			if err != nil {
				return fmt.Errorf("open output file: %w", err)
			}
			defer f.Close()
			out = f
		}

		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(events)
	},
}

func init() {
	scanCmd.Flags().StringVarP(&scanTarget, "target", "t", "", "scan target (required)")
	scanCmd.Flags().StringVarP(&scanModules, "modules", "m", "dns_resolve", "comma-separated module list")
	scanCmd.Flags().StringVarP(&scanOutput, "output", "o", "", "output file (default: stdout)")
	scanCmd.Flags().StringVar(&scanDB, "db", "", "database path (default: in-memory)")
	rootCmd.AddCommand(scanCmd)
}
