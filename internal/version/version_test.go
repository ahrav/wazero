package version

import (
	"strings"
	"testing"
)

func TestGetCompilationCacheVersion(t *testing.T) {
	checked := GetCompilationCacheVersion(false)
	unchecked := GetCompilationCacheVersion(true)
	if strings.HasSuffix(checked, "-nb") {
		t.Fatalf("checked cache version %q ends in -nb", checked)
	}
	if !strings.HasSuffix(unchecked, "-nb") {
		t.Fatalf("unchecked cache version %q does not end in -nb", unchecked)
	}
	if checked == unchecked {
		t.Fatal("checked and unchecked cache versions must differ")
	}
}
