package memoryallocator

import (
	"context"
	"reflect"

	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/internal/expctxkeys"
)

// Identity is the process-local identity of an allocator pointer. It is
// comparable so compilation caches can isolate unsafe engines by allocator.
type Identity struct {
	typ reflect.Type
	ptr uintptr
}

// Config is the memory allocator and any validated unsafe compiler capability
// attached to a context.
type Config struct {
	Allocator          experimental.MemoryAllocator
	BoundsCheckElision bool
	Identity           Identity
}

// FromContext returns the allocator configuration attached by
// experimental.WithMemoryAllocator.
func FromContext(ctx context.Context) Config {
	allocator, _ := ctx.Value(expctxkeys.MemoryAllocatorKey{}).(experimental.MemoryAllocator)
	return FromAllocator(allocator)
}

// FromAllocator validates the opt-in bounds-check-elision report. Invalid,
// nil, and non-pointer capability implementations safely remain in checked
// mode because they cannot provide a stable per-instance identity.
func FromAllocator(allocator experimental.MemoryAllocator) (ret Config) {
	ret.Allocator = allocator
	capability, ok := allocator.(experimental.UnsafeBoundsCheckElisionAllocator)
	if !ok {
		return
	}
	v := reflect.ValueOf(allocator)
	if v.Kind() != reflect.Pointer || v.IsNil() || v.Type().Elem().Size() == 0 {
		return
	}
	addressSpace, guardSize := capability.UnsafeBoundsCheckElisionReservation()
	if addressSpace < experimental.UnsafeBoundsCheckElisionAddressSpace ||
		guardSize < experimental.UnsafeBoundsCheckElisionGuardSize {
		return
	}
	ret.BoundsCheckElision = true
	ret.Identity = Identity{typ: v.Type(), ptr: v.Pointer()}
	return
}
