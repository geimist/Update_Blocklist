package i18n

import "testing"

func TestResolvePriority(t *testing.T) {
	if got := Resolve("fre", "ger", "de"); got != "fre" {
		t.Fatalf("personal wins: %s", got)
	}
	if got := Resolve("def", "ger", "en"); got != "ger" {
		t.Fatalf("dsm wins: %s", got)
	}
	if got := Resolve("", "def", "de-DE,en"); got != "ger" {
		t.Fatalf("browser: %s", got)
	}
	if got := Resolve("", "def", ""); got != "ger" {
		t.Fatalf("fallback: %s", got)
	}
	if got := Resolve("enu", "ger", ""); got != "enu" {
		t.Fatalf("missing catalogue still reports the code: %s", got)
	}
}
