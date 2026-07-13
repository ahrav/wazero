package experimental

import (
	"context"

	"github.com/tetratelabs/wazero/internal/expctxkeys"
)

// MemoryAllocator is a memory allocation hook,
// invoked to create a LinearMemory.
type MemoryAllocator interface {
	// Allocate should create a new LinearMemory with the given specification:
	// cap is the suggested initial capacity for the backing []byte,
	// and max the maximum length that will ever be requested.
	//
	// Notes:
	//   - To back a shared memory, the address of the backing []byte cannot
	//     change. This is checked at runtime. Implementations should document
	//     if the returned LinearMemory meets this requirement.
	Allocate(cap, max uint64) LinearMemory
}

const (
	// UnsafeBoundsCheckElisionAddressSpace is the complete 32-bit WebAssembly
	// address space an allocator must reserve before it can opt into bounds-check
	// elision.
	UnsafeBoundsCheckElisionAddressSpace = uint64(1) << 32
	// UnsafeBoundsCheckElisionGuardSize is the inaccessible tail required after
	// the 32-bit address space. It covers the largest constant offset accepted by
	// the compiler fast path.
	UnsafeBoundsCheckElisionGuardSize = uint64(1) << 16
)

// UnsafeBoundsCheckElisionAllocator is an explicitly unsafe opt-in capability
// for compiler bounds-check elision. Implementations must reserve at least the
// reported address space followed by an inaccessible guard region, keep the
// base address stable, and leave every byte beyond committed WebAssembly memory
// inaccessible. Incorrect implementations can allow arbitrary host-memory
// access.
//
// wazero validates the reported sizes and binds generated code to the exact
// allocator pointer used to create the runtime. It cannot verify that the
// allocator's mappings actually honor this contract.
type UnsafeBoundsCheckElisionAllocator interface {
	MemoryAllocator
	// UnsafeBoundsCheckElisionReservation reports the reserved WebAssembly
	// address space and the inaccessible guard size in bytes.
	UnsafeBoundsCheckElisionReservation() (addressSpace, guardSize uint64)
}

// MemoryAllocatorFunc is a convenience for defining inlining a MemoryAllocator.
type MemoryAllocatorFunc func(cap, max uint64) LinearMemory

// Allocate implements MemoryAllocator.Allocate.
func (f MemoryAllocatorFunc) Allocate(cap, max uint64) LinearMemory {
	return f(cap, max)
}

// LinearMemory is an expandable []byte that backs a Wasm linear memory.
type LinearMemory interface {
	// Reallocates the linear memory to size bytes in length.
	//
	// Notes:
	//   - To back a shared memory, Reallocate can't change the address of the
	//     backing []byte (only its length/capacity may change).
	//   - Reallocate may return nil if fails to grow the LinearMemory. This
	//     condition may or may not be handled gracefully by the Wasm module.
	Reallocate(size uint64) []byte
	// Free the backing memory buffer.
	Free()
}

// WithMemoryAllocator registers the given MemoryAllocator into the given
// context.Context. The context must be passed when initializing a module.
func WithMemoryAllocator(ctx context.Context, allocator MemoryAllocator) context.Context {
	if allocator != nil {
		return context.WithValue(ctx, expctxkeys.MemoryAllocatorKey{}, allocator)
	}
	return ctx
}
