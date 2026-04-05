// Package main is the entry point for the SpiderFoot OSINT automation tool.
package main

import "os"

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
