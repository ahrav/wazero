package memoryallocator

import (
	"context"
	"testing"

	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/internal/testing/require"
)

type testAllocator struct {
	addressSpace uint64
	guardSize    uint64
}

type zeroSizedAllocator struct{}

func (*zeroSizedAllocator) Allocate(uint64, uint64) experimental.LinearMemory { return nil }

func (*zeroSizedAllocator) UnsafeBoundsCheckElisionReservation() (uint64, uint64) {
	return experimental.UnsafeBoundsCheckElisionAddressSpace, experimental.UnsafeBoundsCheckElisionGuardSize
}

func (*testAllocator) Allocate(uint64, uint64) experimental.LinearMemory { return nil }

func (a *testAllocator) UnsafeBoundsCheckElisionReservation() (uint64, uint64) {
	return a.addressSpace, a.guardSize
}

func TestFromAllocator(t *testing.T) {
	valid := &testAllocator{
		addressSpace: experimental.UnsafeBoundsCheckElisionAddressSpace,
		guardSize:    experimental.UnsafeBoundsCheckElisionGuardSize,
	}
	validConfig := FromAllocator(valid)
	require.Equal(t, valid, validConfig.Allocator)
	require.True(t, validConfig.BoundsCheckElision)
	require.NotEqual(t, Identity{}, validConfig.Identity)
	require.Equal(t, validConfig.Identity, FromAllocator(valid).Identity)

	other := *valid
	require.NotEqual(t, validConfig.Identity, FromAllocator(&other).Identity)

	for _, tc := range []struct {
		name      string
		allocator experimental.MemoryAllocator
	}{
		{name: "nil"},
		{name: "ordinary", allocator: experimental.MemoryAllocatorFunc(func(uint64, uint64) experimental.LinearMemory { return nil })},
		{name: "short address space", allocator: &testAllocator{
			addressSpace: experimental.UnsafeBoundsCheckElisionAddressSpace - 1,
			guardSize:    experimental.UnsafeBoundsCheckElisionGuardSize,
		}},
		{name: "short guard", allocator: &testAllocator{
			addressSpace: experimental.UnsafeBoundsCheckElisionAddressSpace,
			guardSize:    experimental.UnsafeBoundsCheckElisionGuardSize - 1,
		}},
		{name: "nil capability pointer", allocator: (*testAllocator)(nil)},
		{name: "zero-sized capability", allocator: &zeroSizedAllocator{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := FromAllocator(tc.allocator)
			require.False(t, config.BoundsCheckElision)
			require.Equal(t, Identity{}, config.Identity)
		})
	}
}

func TestFromContext(t *testing.T) {
	allocator := &testAllocator{
		addressSpace: experimental.UnsafeBoundsCheckElisionAddressSpace,
		guardSize:    experimental.UnsafeBoundsCheckElisionGuardSize,
	}
	config := FromContext(experimental.WithMemoryAllocator(context.Background(), allocator))
	require.Equal(t, allocator, config.Allocator)
	require.True(t, config.BoundsCheckElision)
}
