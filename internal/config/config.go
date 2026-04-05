// Package config loads and serves SpiderFoot-Go configuration.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds all application configuration.
type Config struct {
	// Debug enables verbose debugging output.
	Debug bool `yaml:"debug"`
	// MaxThreads limits concurrent worker execution.
	MaxThreads int `yaml:"max_threads"`
	// DatabasePath is the SQLite database path.
	DatabasePath string `yaml:"database"`
	// UserAgent is the default HTTP user agent string.
	UserAgent string `yaml:"user_agent"`
	// DNSServer is an optional DNS resolver override.
	DNSServer string `yaml:"dns_server"`
	// FetchTimeout is the default network timeout in seconds.
	FetchTimeout int `yaml:"fetch_timeout"`
	// Listen is the web UI listen address.
	Listen string `yaml:"listen"`
	// WebRoot is the base path for the web UI.
	WebRoot string `yaml:"web_root"`
	// APIKey is an optional API key for authenticating web API requests.
	APIKey string `yaml:"api_key"`
	// NoAuth disables authentication enforcement. Must be explicitly set via
	// the --no-auth CLI flag; the server refuses to start without either an
	// API key or this flag.
	NoAuth bool `yaml:"-"`
	// Modules holds module-specific option maps keyed by module name.
	Modules map[string]map[string]any `yaml:"modules"`
}

// Load reads config from YAML file, then overrides with SF_ prefixed env vars,
// then fills defaults.
func Load(configPath string) (*Config, error) {
	cfg := Defaults()

	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("read config %q: %w", configPath, err)
		}

		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config %q: %w", configPath, err)
		}
	}

	if err := applyEnvOverrides(cfg); err != nil {
		return nil, err
	}

	applyDefaults(cfg)
	return cfg, nil
}

// ModuleOpts returns options for a specific module merged with defaults.
func (c *Config) ModuleOpts(moduleName string) map[string]any {
	out := make(map[string]any)
	if c == nil || c.Modules == nil {
		return out
	}

	for _, key := range []string{"default", "__default__"} {
		for k, v := range c.Modules[key] {
			out[k] = v
		}
	}

	for k, v := range c.Modules[moduleName] {
		out[k] = v
	}

	return out
}

func applyEnvOverrides(cfg *Config) error {
	var errs []error

	if v, ok := os.LookupEnv("SF_DEBUG"); ok {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("parse SF_DEBUG: %w", err))
		} else {
			cfg.Debug = parsed
		}
	}

	if v, ok := lookupEnvAny("SF_MAX_THREADS"); ok {
		parsed, err := strconv.Atoi(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("parse SF_MAX_THREADS: %w", err))
		} else {
			cfg.MaxThreads = parsed
		}
	}

	if v, ok := lookupEnvAny("SF_DATABASE", "SF_DATABASE_PATH"); ok {
		cfg.DatabasePath = v
	}

	if v, ok := lookupEnvAny("SF_USER_AGENT"); ok {
		cfg.UserAgent = v
	}

	if v, ok := lookupEnvAny("SF_DNS_SERVER"); ok {
		cfg.DNSServer = v
	}

	if v, ok := lookupEnvAny("SF_FETCH_TIMEOUT"); ok {
		parsed, err := strconv.Atoi(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("parse SF_FETCH_TIMEOUT: %w", err))
		} else {
			cfg.FetchTimeout = parsed
		}
	}

	if v, ok := lookupEnvAny("SF_LISTEN"); ok {
		cfg.Listen = v
	}

	if v, ok := lookupEnvAny("SF_WEB_ROOT"); ok {
		cfg.WebRoot = v
	}

	if v, ok := lookupEnvAny("SF_API_KEY"); ok {
		cfg.APIKey = v
	}

	return errors.Join(errs...)
}

func lookupEnvAny(keys ...string) (string, bool) {
	for _, key := range keys {
		if value, ok := os.LookupEnv(key); ok {
			return value, true
		}
	}

	return "", false
}

func applyDefaults(cfg *Config) {
	defaults := Defaults()

	if cfg.MaxThreads == 0 {
		cfg.MaxThreads = defaults.MaxThreads
	}

	if strings.TrimSpace(cfg.DatabasePath) == "" {
		cfg.DatabasePath = defaults.DatabasePath
	}

	if strings.TrimSpace(cfg.UserAgent) == "" {
		cfg.UserAgent = defaults.UserAgent
	}

	if cfg.FetchTimeout == 0 {
		cfg.FetchTimeout = defaults.FetchTimeout
	}

	if strings.TrimSpace(cfg.Listen) == "" {
		cfg.Listen = defaults.Listen
	}

	if strings.TrimSpace(cfg.WebRoot) == "" {
		cfg.WebRoot = defaults.WebRoot
	}

	if cfg.Modules == nil {
		cfg.Modules = make(map[string]map[string]any)
	}
}
