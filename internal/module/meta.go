package module

// Meta holds module metadata.
type Meta struct {
	// Name is the module's unique identifier.
	Name string
	// Summary is a short human-readable description.
	Summary string
	// Categories groups the module into one or more classifications.
	Categories []string
	// UseCases describes the situations the module is intended for.
	UseCases []string
	// Flags records optional module capabilities or behaviors.
	Flags []string
}
