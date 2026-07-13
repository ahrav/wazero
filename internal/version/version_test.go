package version

import (
	"strings"
	"sync"
	"testing"
)

func TestUnsafeSkipBoundsChecksEnabledCapturedOnFirstUse(t *testing.T) {
	reset := func() {
		unsafeSkipBoundsOnce = sync.Once{}
		unsafeSkipBounds = false
	}
	t.Cleanup(reset)

	t.Setenv("WAZERO_UNSAFE_SKIP_BOUNDS", "1")
	reset()
	if !UnsafeSkipBoundsChecksEnabled() {
		t.Fatal("bounds-check elision should be enabled")
	}
	if got := GetCompilationCacheVersion(); !strings.HasSuffix(got, "-nb") {
		t.Fatalf("unchecked cache version %q does not end in -nb", got)
	}

	t.Setenv("WAZERO_UNSAFE_SKIP_BOUNDS", "0")
	if !UnsafeSkipBoundsChecksEnabled() {
		t.Fatal("compiler mode changed after first use")
	}
}
