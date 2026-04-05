package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()

	if cfg.Debug {
		t.Fatal("Defaults().Debug = true, want false")
	}

	if cfg.MaxThreads != 3 {
		t.Fatalf("Defaults().MaxThreads = %d, want 3", cfg.MaxThreads)
	}

	if cfg.DatabasePath != "~/.spiderfoot/spiderfoot.db" {
		t.Fatalf("Defaults().DatabasePath = %q", cfg.DatabasePath)
	}

	if cfg.UserAgent != "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0" {
		t.Fatalf("Defaults().UserAgent = %q", cfg.UserAgent)
	}

	if cfg.DNSServer != "" {
		t.Fatalf("Defaults().DNSServer = %q, want empty", cfg.DNSServer)
	}

	if cfg.FetchTimeout != 5 {
		t.Fatalf("Defaults().FetchTimeout = %d, want 5", cfg.FetchTimeout)
	}

	if cfg.Listen != "127.0.0.1:5001" {
		t.Fatalf("Defaults().Listen = %q", cfg.Listen)
	}

	if cfg.WebRoot != "/" {
		t.Fatalf("Defaults().WebRoot = %q", cfg.WebRoot)
	}

	if cfg.Modules == nil {
		t.Fatal("Defaults().Modules = nil")
	}
}

func TestLoadFromYAMLFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	content := []byte(`
debug: true
max_threads: 7
database: /tmp/spiderfoot.db
user_agent: TestAgent/1.0
dns_server: 1.1.1.1
fetch_timeout: 11
listen: 0.0.0.0:9000
web_root: /spiderfoot
modules:
  default:
    timeout: 5
  sfp_dns:
    api_key: abc123
`)

	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if !cfg.Debug || cfg.MaxThreads != 7 || cfg.DatabasePath != "/tmp/spiderfoot.db" ||
		cfg.UserAgent != "TestAgent/1.0" || cfg.DNSServer != "1.1.1.1" ||
		cfg.FetchTimeout != 11 || cfg.Listen != "0.0.0.0:9000" || cfg.WebRoot != "/spiderfoot" {
		t.Fatalf("Load() returned unexpected config: %+v", cfg)
	}

	if got := cfg.Modules["sfp_dns"]["api_key"]; got != "abc123" {
		t.Fatalf("Load() module option = %v, want %q", got, "abc123")
	}
}

func TestLoadEmptyPathUsesDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\") error = %v", err)
	}

	defaults := Defaults()
	if cfg.Debug != defaults.Debug ||
		cfg.MaxThreads != defaults.MaxThreads ||
		cfg.DatabasePath != defaults.DatabasePath ||
		cfg.UserAgent != defaults.UserAgent ||
		cfg.DNSServer != defaults.DNSServer ||
		cfg.FetchTimeout != defaults.FetchTimeout ||
		cfg.Listen != defaults.Listen ||
		cfg.WebRoot != defaults.WebRoot {
		t.Fatalf("Load(\"\") = %+v, want %+v", cfg, defaults)
	}

	if cfg.Modules == nil {
		t.Fatal("Load(\"\").Modules = nil")
	}
}

func TestLoadEnvOverride(t *testing.T) {
	t.Setenv("SF_DEBUG", "true")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if !cfg.Debug {
		t.Fatal("Load() did not apply SF_DEBUG override")
	}
}

func TestModuleOpts(t *testing.T) {
	cfg := &Config{
		Modules: map[string]map[string]any{
			"default": {
				"timeout": 5,
				"retries": 2,
			},
			"sfp_dns": {
				"timeout": 10,
				"api_key": "secret",
			},
		},
	}

	got := cfg.ModuleOpts("sfp_dns")

	if got["timeout"] != 10 {
		t.Fatalf("ModuleOpts()[timeout] = %v, want 10", got["timeout"])
	}

	if got["retries"] != 2 {
		t.Fatalf("ModuleOpts()[retries] = %v, want 2", got["retries"])
	}

	if got["api_key"] != "secret" {
		t.Fatalf("ModuleOpts()[api_key] = %v, want %q", got["api_key"], "secret")
	}
}
