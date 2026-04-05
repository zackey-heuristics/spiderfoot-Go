// Package webui implements the SpiderFoot-Go web interface and REST API.
package webui

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/config"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/db"
)

// Server is the SpiderFoot web UI HTTP server.
type Server struct {
	database *db.DB
	cfg      *config.Config
	mux      *http.ServeMux
}

// New creates a new web UI server and registers all routes.
func New(database *db.DB, cfg *config.Config) *Server {
	s := &Server{database: database, cfg: cfg, mux: http.NewServeMux()}
	s.routes()
	return s
}

// Handler returns the underlying HTTP handler, wrapped with middleware.
func (s *Server) Handler() http.Handler {
	return s.applyMiddleware(s.mux)
}

// ListenAndServe starts the HTTP server. It shuts down gracefully when ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.cfg.NoAuth {
		slog.Warn("running without authentication (--no-auth); all endpoints are unprotected",
			"listen", s.cfg.Listen)
	}
	if s.cfg.APIKey == "" && !s.cfg.NoAuth && !isLocalhost(s.cfg.Listen) {
		slog.Warn("web API has no authentication and is listening on a non-localhost address",
			"listen", s.cfg.Listen)
	}

	srv := &http.Server{
		Addr:        s.cfg.Listen,
		Handler:     s.applyMiddleware(s.mux),
		BaseContext: func(_ net.Listener) context.Context { return ctx },
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// applyMiddleware chains CSRF and API key middleware around the handler.
func (s *Server) applyMiddleware(next http.Handler) http.Handler {
	return s.apiKeyMiddleware(s.csrfMiddleware(next))
}

// apiKeyMiddleware enforces Bearer token authentication on /api/ routes.
// Non-API routes (GET /, /ping, static assets) are accessible without auth
// so the browser UI works. When NoAuth is set, all requests pass through.
func (s *Server) apiKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := s.cfg.APIKey
		if key == "" {
			next.ServeHTTP(w, r)
			return
		}
		// Only enforce auth on API routes.
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		token := strings.TrimPrefix(auth, "Bearer ")
		if !strings.HasPrefix(auth, "Bearer ") || subtle.ConstantTimeCompare([]byte(token), []byte(key)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// csrfMiddleware protects POST routes from cross-site request forgery by
// checking the Origin header. Requests with an API key (Authorization header)
// are exempt since CSRF is a browser-only attack vector.
func (s *Server) csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}

		// API-key authenticated requests are not susceptible to CSRF.
		if r.Header.Get("Authorization") != "" {
			next.ServeHTTP(w, r)
			return
		}

		origin := r.Header.Get("Origin")
		if origin == "" {
			// No Origin header — likely not a browser request (curl, etc.).
			next.ServeHTTP(w, r)
			return
		}

		// Verify Origin matches the server's listen address.
		if !isAllowedOrigin(origin, s.cfg.Listen) {
			http.Error(w, "forbidden: cross-origin request", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isAllowedOrigin checks if the request origin matches the server listen address.
func isAllowedOrigin(origin, listenAddr string) bool {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return false
	}
	if host == "" || host == "0.0.0.0" {
		// When listening on all interfaces, accept localhost origins.
		for _, h := range []string{"127.0.0.1", "localhost", "::1"} {
			if matchOrigin(origin, h, port) {
				return true
			}
		}
		return false
	}
	return matchOrigin(origin, host, port)
}

// matchOrigin checks if origin matches http(s)://host:port.
func matchOrigin(origin, host, port string) bool {
	for _, scheme := range []string{"http://", "https://"} {
		expected := scheme + net.JoinHostPort(host, port)
		if origin == expected {
			return true
		}
		// Browsers omit default ports (80/443).
		if (scheme == "http://" && port == "80") || (scheme == "https://" && port == "443") {
			if origin == scheme+host {
				return true
			}
		}
	}
	return false
}

// isLocalhost returns true if the listen address refers to a loopback interface.
func isLocalhost(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}
