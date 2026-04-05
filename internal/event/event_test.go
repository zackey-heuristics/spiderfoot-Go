package event

import "testing"

func TestRegistryIncludesExpectedTypes(t *testing.T) {
	t.Parallel()

	registry := Registry()
	root, ok := registry[ROOT]
	if !ok {
		t.Fatal("ROOT missing from registry")
	}

	if root.Category != "INTERNAL" {
		t.Fatalf("unexpected ROOT category: %q", root.Category)
	}

	raw, ok := registry[RAW_DNS_RECORDS]
	if !ok {
		t.Fatal("RAW_DNS_RECORDS missing from registry")
	}

	if !raw.IsRaw {
		t.Fatal("RAW_DNS_RECORDS should be marked raw")
	}

	if _, ok := registry[WEBSERVER_URL_EXTERNAL]; !ok {
		t.Fatal("WEBSERVER_URL_EXTERNAL missing from registry")
	}
}

func TestNewRootEvent(t *testing.T) {
	t.Parallel()

	evt, err := New(ROOT, "example.com", "", nil)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if got := evt.Hash(); got != string(ROOT) {
		t.Fatalf("Hash() = %q, want %q", got, ROOT)
	}

	if got := evt.SourceEventHash(); got != string(ROOT) {
		t.Fatalf("SourceEventHash() = %q, want %q", got, ROOT)
	}

	m := evt.AsMap()
	if got := m["source"]; got != "" {
		t.Fatalf("AsMap()[source] = %v, want empty string", got)
	}
}

func TestNewNonRootEvent(t *testing.T) {
	t.Parallel()

	root, err := New(ROOT, "example.com", "", nil)
	if err != nil {
		t.Fatalf("New root returned error: %v", err)
	}

	child, err := New(DOMAIN_NAME, "api.example.com", "sfp_dnsresolve", root)
	if err != nil {
		t.Fatalf("New child returned error: %v", err)
	}

	if child.SourceEvent != root {
		t.Fatal("child source event mismatch")
	}

	if got := child.SourceEventHash(); got != root.Hash() {
		t.Fatalf("SourceEventHash() = %q, want %q", got, root.Hash())
	}

	if got := child.Hash(); got == "" || got == string(ROOT) {
		t.Fatalf("Hash() = %q, want non-empty non-ROOT hash", got)
	}

	m := child.AsMap()
	if got := m["type"]; got != string(DOMAIN_NAME) {
		t.Fatalf("AsMap()[type] = %v, want %q", got, DOMAIN_NAME)
	}

	if got := m["source"]; got != root.Data {
		t.Fatalf("AsMap()[source] = %v, want %q", got, root.Data)
	}
}

func TestNewValidation(t *testing.T) {
	t.Parallel()

	root, err := New(ROOT, "example.com", "", nil)
	if err != nil {
		t.Fatalf("New root returned error: %v", err)
	}

	cases := []struct {
		name string
		typ  Type
		data string
		mod  string
		src  *Event
	}{
		{name: "empty type", data: "x", mod: "mod", src: root},
		{name: "empty data", typ: DOMAIN_NAME, mod: "mod", src: root},
		{name: "empty module", typ: DOMAIN_NAME, data: "x", src: root},
		{name: "nil source", typ: DOMAIN_NAME, data: "x", mod: "mod"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.typ, tc.data, tc.mod, tc.src); err == nil {
				t.Fatal("New returned nil error, want validation failure")
			}
		})
	}
}
