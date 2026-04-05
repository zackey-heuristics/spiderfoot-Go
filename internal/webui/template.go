package webui

import (
	"html/template"
	"io/fs"
	"net/http"
)

// pageData holds common data passed to every template.
type pageData struct {
	// PageID identifies the active nav item (SCANLIST, NEWSCAN, SCANINFO, SETTINGS).
	PageID string
	// DocRoot is the base path for URLs (usually empty string for root).
	DocRoot string
	// Version is the application version string.
	Version string
	// Data carries page-specific payload.
	Data any
}

// parseTemplates parses the base template together with each page template.
// Returns a map of page name -> compiled template.
func parseAllTemplates() (map[string]*template.Template, error) {
	sub, err := fs.Sub(templateFS, "templates")
	if err != nil {
		return nil, err
	}

	pages := []string{"scanlist.html", "newscan.html", "scaninfo.html", "settings.html"}
	templates := make(map[string]*template.Template, len(pages))

	for _, page := range pages {
		t, err := template.ParseFS(sub, "base.html", page)
		if err != nil {
			return nil, err
		}
		templates[page] = t
	}
	return templates, nil
}

// renderPage executes the appropriate page template.
func (s *Server) renderPage(w http.ResponseWriter, page string, data pageData) {
	if data.DocRoot == "" {
		data.DocRoot = s.cfg.WebRoot
		if data.DocRoot == "/" {
			data.DocRoot = ""
		}
	}
	if data.Version == "" {
		data.Version = "dev"
	}

	tmpl, ok := s.templates[page]
	if !ok {
		http.Error(w, "template not found: "+page, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}
