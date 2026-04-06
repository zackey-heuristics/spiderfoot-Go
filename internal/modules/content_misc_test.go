package modules

import (
	"context"
	"testing"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

func TestCompanyExtractor(t *testing.T) {
	body := "We work with Acme Corporation and Globex Inc. on this project."
	results := runExtractor(t, "company", body)
	if len(results) < 2 {
		t.Fatalf("expected at least 2 companies, got %d", len(results))
	}
}

func TestCountryNameExtractor(t *testing.T) {
	body := "Offices in United States, Japan, and Germany."
	results := runExtractor(t, "countryname", body)
	if len(results) < 3 {
		t.Fatalf("expected at least 3 countries, got %d", len(results))
	}
}

func TestInterestingFilesExtractor(t *testing.T) {
	body := `Visit /admin/ or /wp-admin/ for control panel. Backup at /backup.sql`
	results := runExtractor(t, "intfiles", body)
	if len(results) < 2 {
		t.Fatalf("expected at least 2 interesting paths, got %d", len(results))
	}
}

func TestJunkFilesExtractor(t *testing.T) {
	body := "Check http://example.com/index.php.bak and http://example.com/old/config.old"
	results := runExtractor(t, "junkfiles", body)
	if len(results) < 2 {
		t.Fatalf("expected at least 2 junk files, got %d", len(results))
	}
}

func TestWebAnalyticsExtractor(t *testing.T) {
	body := `<script>ga('create', 'UA-12345678-1', 'auto');</script>
<script>gtag('config', 'G-ABCDEFGHIJ');</script>`
	results := runExtractor(t, "webanalytics", body)
	if len(results) < 2 {
		t.Fatalf("expected at least 2 analytics IDs, got %d", len(results))
	}
}

func TestPGPExtractor(t *testing.T) {
	body := `Some text
-----BEGIN PGP PUBLIC KEY BLOCK-----
mQINBGTest1234567890
-----END PGP PUBLIC KEY BLOCK-----
end`
	results := runExtractor(t, "pgp", body)
	if len(results) != 1 {
		t.Fatalf("expected 1 PGP key, got %d", len(results))
	}
}

func TestSimilarDomainModule(t *testing.T) {
	factory, ok := module.Get("similar")
	if !ok {
		t.Fatal("similar module not registered")
	}
	mod := factory()
	_ = mod.Setup(nil)

	root, _ := event.New(event.ROOT, "test", "", nil)
	evt, _ := event.New(event.DOMAIN_NAME, "google.com", "test", root)

	results, err := mod.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("expected typosquat variants")
	}
	for _, r := range results {
		if r.Type != event.SIMILARDOMAIN {
			t.Fatalf("expected SIMILARDOMAIN, got %s", r.Type)
		}
	}
}

func TestSimilarDomainMeta(t *testing.T) {
	m := &SimilarDomain{}
	if m.Meta().Name != "similar" {
		t.Fatal("wrong name")
	}
	if len(m.WatchedEvents()) != 1 {
		t.Fatal("expected 1 watched event")
	}
	if len(m.ProducedEvents()) != 1 {
		t.Fatal("expected 1 produced event")
	}
	results, err := m.HandleEvent(context.Background(), nil)
	if err != nil || results != nil {
		t.Fatal("expected nil/nil for nil event")
	}
}

func TestGenerateTyposquats(t *testing.T) {
	variants := generateTyposquats("test", "com")
	if len(variants) < 5 {
		t.Fatalf("expected at least 5 variants, got %d", len(variants))
	}
}

func TestFileMetaModule(t *testing.T) {
	factory, ok := module.Get("filemeta")
	if !ok {
		t.Fatal("filemeta module not registered")
	}
	mod := factory()
	_ = mod.Setup(nil)

	root, _ := event.New(event.ROOT, "test", "", nil)
	body := `Documents at https://example.com/report.pdf and https://example.com/data.xlsx`
	evt, _ := event.New(event.TARGET_WEB_CONTENT, body, "spider", root)

	results, err := mod.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 file URLs, got %d", len(results))
	}
}

func TestFileMetaMeta(t *testing.T) {
	m := &FileMeta{}
	if m.Meta().Name != "filemeta" {
		t.Fatal("wrong name")
	}
	if len(m.WatchedEvents()) != 2 {
		t.Fatal("expected 2 watched events")
	}
	if len(m.ProducedEvents()) != 1 {
		t.Fatal("expected 1 produced event")
	}
	results, err := m.HandleEvent(context.Background(), nil)
	if err != nil || results != nil {
		t.Fatal("expected nil/nil for nil event")
	}
	if err := m.Finish(); err != nil {
		t.Fatal(err)
	}
}

func TestContentMiscMetaAndEvents(t *testing.T) {
	names := []string{"company", "countryname", "intfiles", "junkfiles", "webanalytics", "pgp", "similar", "filemeta"}
	for _, name := range names {
		factory, ok := module.Get(name)
		if !ok {
			t.Errorf("module %q not registered", name)
			continue
		}
		mod := factory()
		meta := mod.Meta()
		if meta.Name != name {
			t.Errorf("module %q has Meta name %q", name, meta.Name)
		}
		if meta.Summary == "" {
			t.Errorf("module %q has empty summary", name)
		}
	}
}
