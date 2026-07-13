package version

import (
	"os"
	"runtime/debug"
	"strings"
	"sync"
)

// Default is the default version value used when none was found.
const Default = "dev"

// version holds the current version from the go.mod of downstream users or set by ldflag for wazero CLI.
var version string

// The bounds-check cache salt isolates compilation caches produced with
// WAZERO_UNSAFE_SKIP_BOUNDS=1 (explicit bounds checks elided) from those
// produced without it, so unchecked machine code is never loaded by a checked
// build (or vice versa). The mode is captured on first use so an embedding
// library can configure it before creating an engine, while the frontend and
// cache key still cannot diverge if the environment changes later.
//
// It is deliberately applied only in GetCompilationCacheVersion (the cache
// key), NOT in GetWazeroVersion, so that the CLI's exact `== Default`
// dev-mode checks and the `version` subcommand output are unaffected. Applying
// it at the cache boundary also isolates every build type uniformly — release,
// dev/replace, and `-ldflags -X ...version.version=...` — without special
// casing any GetWazeroVersion return path.
var (
	unsafeSkipBoundsOnce sync.Once
	unsafeSkipBounds     bool
)

// UnsafeSkipBoundsChecksEnabled returns the process-wide compiler mode. The
// first caller snapshots the environment for both lowering and cache keys.
func UnsafeSkipBoundsChecksEnabled() bool {
	unsafeSkipBoundsOnce.Do(func() {
		unsafeSkipBounds = os.Getenv("WAZERO_UNSAFE_SKIP_BOUNDS") == "1"
	})
	return unsafeSkipBounds
}

// GetCompilationCacheVersion returns the version string used to key the wazevo
// compilation cache (both the on-disk cache directory and the serialized cache
// header). It augments GetWazeroVersion with the bounds-check mode so machine
// code compiled with WAZERO_UNSAFE_SKIP_BOUNDS=1 is never loaded from — or
// written to — a cache belonging to a build without it, and vice versa. Keep
// this and GetWazeroVersion in sync at every cache site so the directory key
// and the header check never disagree.
func GetCompilationCacheVersion() string {
	if UnsafeSkipBoundsChecksEnabled() {
		return GetWazeroVersion() + "-nb"
	}
	return GetWazeroVersion()
}

// GetWazeroVersion returns the current version of wazero either in the go.mod or set by ldflag for wazero CLI.
//
// If this is not CLI, this assumes that downstream users of wazero imports wazero as "github.com/tetratelabs/wazero".
// To be precise, the returned string matches the require statement there.
// For example, if the go.mod has "require github.com/tetratelabs/wazero 0.1.2-12314124-abcd",
// then this returns "0.1.2-12314124-abcd".
//
// Note: this is tested in ./testdata/main_test.go with a separate go.mod to pretend as the wazero user.
func GetWazeroVersion() (ret string) {
	if len(version) != 0 {
		return version
	}

	info, ok := debug.ReadBuildInfo()
	if ok {
		for _, dep := range info.Deps {
			// Note: here's the assumption that wazero is imported as github.com/tetratelabs/wazero.
			if strings.Contains(dep.Path, "github.com/tetratelabs/wazero") {
				ret = dep.Version
			}
		}

		// In wazero CLI, wazero is a main module, so we have to get the version info from info.Main.
		if versionMissing(ret) {
			ret = info.Main.Version
		}
	}
	if versionMissing(ret) {
		return Default // don't return parens
	}

	// Cache for the subsequent calls.
	// Salt the version so compilation caches from the unpatched runtime are
	// never shared with this fork (SSA differs for shared-memory modules).
	ret += "-re2fixedmem1"
	version = ret
	return ret
}

func versionMissing(ret string) bool {
	return ret == "" || ret == "(devel)" // pkg.go defaults to (devel)
}
