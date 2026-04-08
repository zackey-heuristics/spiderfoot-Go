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

	applyModuleEnvOverrides(cfg)

	return errors.Join(errs...)
}

// applyModuleEnvOverrides scans os.Environ() for variables of the form
// SF_MODULE_<MOD>_<KEY>=<value> and injects them into cfg.Modules[mod][key].
// The module name and key are lowercased. The module/key split is on the
// first underscore after the SF_MODULE_ prefix, so module names must not
// contain underscores (all registered SpiderFoot-Go module names are
// single-word). Values override any prior YAML setting for the same key.
func applyModuleEnvOverrides(cfg *Config) {
	const prefix = "SF_MODULE_"
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, prefix) {
			continue
		}
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}
		rest := kv[len(prefix):eq]
		val := kv[eq+1:]
		us := strings.IndexByte(rest, '_')
		if us <= 0 || us == len(rest)-1 {
			continue
		}
		mod := strings.ToLower(rest[:us])
		key := strings.ToLower(rest[us+1:])
		if cfg.Modules == nil {
			cfg.Modules = make(map[string]map[string]any)
		}
		if cfg.Modules[mod] == nil {
			cfg.Modules[mod] = make(map[string]any)
		}
		cfg.Modules[mod][key] = val
	}
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
