package config

// Defaults returns default configuration.
func Defaults() *Config {
	return &Config{
		Debug:        false,
		MaxThreads:   3,
		DatabasePath: "~/.spiderfoot/spiderfoot.db",
		UserAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
		DNSServer:    "",
		FetchTimeout: 5,
		Listen:       "127.0.0.1:5001",
		WebRoot:      "/",
		Modules:      make(map[string]map[string]any),
	}
}
