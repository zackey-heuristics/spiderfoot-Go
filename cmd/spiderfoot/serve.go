package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/db"
	_ "github.com/zackey-heuristics/spiderfoot-Go/internal/modules"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/webui"
)

var (
	listenAddr string
	noAuth     bool
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the web UI server",
	RunE: func(_ *cobra.Command, _ []string) error {
		if listenAddr != "" {
			cfg.Listen = listenAddr
		}

		// Require explicit auth configuration.
		if cfg.APIKey == "" && !noAuth {
			return fmt.Errorf("no API key configured; set api_key in config, SF_API_KEY env var, or pass --no-auth to run without authentication")
		}
		cfg.NoAuth = noAuth

		dbPath := expandHome(cfg.DatabasePath)
		if dir := filepath.Dir(dbPath); dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("create database directory: %w", err)
			}
		}

		database, err := db.Open(dbPath)
		if err != nil {
			return fmt.Errorf("open database: %w", err)
		}
		defer database.Close()

		srv := webui.New(database, cfg)

		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		slog.Info("starting web server", "listen", cfg.Listen)
		return srv.ListenAndServe(ctx)
	},
}

func init() {
	serveCmd.Flags().StringVarP(&listenAddr, "listen", "l", "", "override listen address (host:port)")
	serveCmd.Flags().BoolVar(&noAuth, "no-auth", false, "run without API key authentication (INSECURE)")
	rootCmd.AddCommand(serveCmd)
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[2:])
	}
	return path
}
