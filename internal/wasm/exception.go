package wasm

import "unsafe"

// Exception represents a thrown WebAssembly exception.
type Exception struct {
	// Tag is the tag instance that was thrown.
	Tag *TagInstance
	// Params holds the argument values matching the tag's function type params.
	Params []uint64
	// Refs is a side table, index-correlated with Params, holding the Go
	// pointer behind a param that carries a reference as an opaque uint64,
	// so Go's GC keeps it alive for as long as the exception is. nil when
	// no param carries one.
	Refs []unsafe.Pointer
}
