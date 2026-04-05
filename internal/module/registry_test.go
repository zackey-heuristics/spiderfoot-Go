package module

import (
	"context"
	"testing"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
)

type testModule struct{}

func (testModule) Meta() Meta { return Meta{Name: "test"} }

func (testModule) Setup(map[string]any) error { return nil }

func (testModule) WatchedEvents() []event.Type { return []event.Type{event.ROOT} }

func (testModule) ProducedEvents() []event.Type { return []event.Type{event.DOMAIN_NAME} }

func (testModule) HandleEvent(_ context.Context, _ *event.Event) ([]*event.Event, error) {
	return nil, nil
}

func (testModule) Finish() error { return nil }

func TestRegisterAndGet(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	factory := func() Module { return testModule{} }
	Register("alpha", factory)

	got, ok := Get("alpha")
	if !ok {
		t.Fatal("Get() reported missing registered module")
	}

	if got == nil {
		t.Fatal("Get() returned nil factory")
	}

	if got().Meta().Name != "test" {
		t.Fatalf("Get() returned unexpected module metadata: %+v", got().Meta())
	}
}

func TestAllSorted(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	factory := func() Module { return testModule{} }
	Register("zeta", factory)
	Register("alpha", factory)
	Register("beta", factory)

	got := All()
	want := []string{"alpha", "beta", "zeta"}

	if len(got) != len(want) {
		t.Fatalf("All() length = %d, want %d", len(got), len(want))
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("All()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestGetMissing(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	if _, ok := Get("missing"); ok {
		t.Fatal("Get() reported existing module for missing key")
	}
}

func TestResetClears(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	Register("alpha", func() Module { return testModule{} })
	Reset()

	if got := All(); len(got) != 0 {
		t.Fatalf("All() after Reset() = %v, want empty", got)
	}

	if _, ok := Get("alpha"); ok {
		t.Fatal("Get() found module after Reset()")
	}
}

func TestRegisterDuplicatePanics(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	Register("alpha", func() Module { return testModule{} })

	defer func() {
		if recover() == nil {
			t.Fatal("Register() did not panic on duplicate name")
		}
	}()

	Register("alpha", func() Module { return testModule{} })
}
