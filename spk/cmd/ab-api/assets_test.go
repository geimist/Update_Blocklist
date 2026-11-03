package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInjectUIAssetVer(t *testing.T) {
	in := `<link rel="stylesheet" href="app.css">
<script src="app.js?v=1.0.28"></script>`
	got := injectUIAssetVer(in, "1710000000")
	want := `<link rel="stylesheet" href="app.css?v=1710000000">
<script src="app.js?v=1710000000"></script>`
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestUIAssetVerUsesNewestMtime(t *testing.T) {
	dir := t.TempDir()
	css := filepath.Join(dir, "app.css")
	js := filepath.Join(dir, "app.js")
	if err := os.WriteFile(css, []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(js, []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	older := time.Unix(1_700_000_000, 0)
	newer := time.Unix(1_700_000_500, 0)
	if err := os.Chtimes(css, older, older); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(js, newer, newer); err != nil {
		t.Fatal(err)
	}
	if got := uiAssetVer(dir); got != "1700000500" {
		t.Fatalf("got %q, want 1700000500", got)
	}
}
