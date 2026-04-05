package main

import (
	"github.com/spf13/cobra"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/config"
)

var (
	cfgPath string
	debug   bool
	cfg     *config.Config
)

var rootCmd = &cobra.Command{
	Use:   "spiderfoot",
	Short: "SpiderFoot OSINT automation tool",
	PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
		c, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		if debug {
			c.Debug = true
		}
		cfg = c
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgPath, "config", "c", "", "path to config file")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "enable debug output")
}
