package version

import (
	"os"
	"runtime/debug"
	"strings"
)

// Default is the default version value used when none was found.
const Default = "dev"

// version holds the current version from the go.mod of downstream users or set by ldflag for wazero CLI.
var version string

// boundsCacheSalt isolates compilation caches produced with
// WAZERO_UNSAFE_SKIP_BOUNDS=1 (explicit bounds checks elided) from those
// produced without it, so unchecked machine code is never loaded by a checked
// build (or vice versa). It is captured once at process start — the same point
// the frontend captures the flag — so the two cannot diverge if the
// environment changes between engine creation and module compilation. It must
// be applied on every code path that produces a version string, including the
// dev/replace fallback below.
var boundsCacheSalt = func() string {
	if os.Getenv("WAZERO_UNSAFE_SKIP_BOUNDS") == "1" {
		return "-nb"
	}
	return ""
}()

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
		// Even in dev/replace builds where no module version is available,
		// salt the cache version so unchecked (no-bounds) machine code is
		// never shared with a checked build.
		version = Default + boundsCacheSalt // don't return parens
		return version
	}

	// Cache for the subsequent calls.
	// Salt the version so compilation caches from the unpatched runtime are
	// never shared with this fork (SSA differs for shared-memory modules).
	ret += "-re2fixedmem1" + boundsCacheSalt
	version = ret
	return ret
}

func versionMissing(ret string) bool {
	return ret == "" || ret == "(devel)" // pkg.go defaults to (devel)
}
