package main

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"autoban/internal/appdb"
)

func TestTelemetryShowPrompt(t *testing.T) {
	if telemetryShowPrompt("", "1", "1.0", "", true) {
		t.Fatal("empty version")
	}
	if telemetryShowPrompt("1.0", "1", "1.0", "", true) {
		t.Fatal("already answered")
	}
	if telemetryShowPrompt("1.0", "", "", "1.0", true) {
		t.Fatal("deferred")
	}
	if !telemetryShowPrompt("1.0", "", "", "", true) {
		t.Fatal("should ask")
	}
	if telemetryShowPrompt("1.0", "", "", "", false) {
		t.Fatal("no successful run")
	}
	if !telemetryShowPrompt("1.1", "1", "1.0", "", true) {
		t.Fatal("new version should ask again")
	}
}

func TestTelemetryQueryOmitsUnsetWorks(t *testing.T) {
	f := telemetryFields{UUID: "u", Device: "DS920+", DSM: "7.2", DSMBuild: "1", Version: "1.0.1", Arch: "x86_64"}
	if _, ok := telemetryQuery(f, "")["works"]; ok {
		t.Fatal("unset works must be omitted")
	}
	q := telemetryQuery(f, "0")
	if q.Get("works") != "0" || q.Get("device") != "DS920+" {
		t.Fatal(q.Encode())
	}
	if _, err := url.ParseQuery(q.Encode()); err != nil {
		t.Fatal(err)
	}
}

func TestFileKV(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "INFO")
	if err := os.WriteFile(path, []byte("version=\"1.2.3\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := fileKV(path, "version"); got != "1.2.3" {
		t.Fatalf("got %q", got)
	}
	if fileKV(path, "missing") != "" {
		t.Fatal("missing key")
	}
}

func TestStateAndSuccess(t *testing.T) {
	dir := t.TempDir()
	db, err := appdb.Open(filepath.Join(dir, "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ok, err := appdb.HasSuccessfulRun(db)
	if err != nil || ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if err := appdb.SetState(db, "telemetry_works", "1"); err != nil {
		t.Fatal(err)
	}
	got, err := appdb.GetState(db, "telemetry_works")
	if err != nil || got != "1" {
		t.Fatalf("got %q err %v", got, err)
	}
	if err := appdb.InsertRun(db, appdb.Run{StartedAt: time.Now().Unix(), Status: "ok"}); err != nil {
		t.Fatal(err)
	}
	ok, err = appdb.HasSuccessfulRun(db)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	id, err := newTelemetryUUID()
	if err != nil || !telemetryUUIDRe.MatchString(id) {
		t.Fatalf("uuid %q err %v", id, err)
	}
}

func TestTelemetryAccepted(t *testing.T) {
	if !telemetryOKRe.MatchString(`{"status":"success"}`) {
		t.Fatal("success")
	}
	if !telemetryOKRe.MatchString("{\"status\" : \"success\"}") {
		t.Fatal("spaced")
	}
	if telemetryOKRe.MatchString(`{"status":"error","message":"success"}`) {
		t.Fatal("error body")
	}
}
