package backup

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func snap(t *testing.T, name string, when time.Time) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name+".db")
	if err := os.WriteFile(p, []byte(name), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, when, when); err != nil {
		t.Fatal(err)
	}
	return p
}

func readSlot(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name+".db"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRotateCascade(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	if err := Rotate(dir, snap(t, "A", t0), t0); err != nil {
		t.Fatal(err)
	}
	if readSlot(t, dir, Pristine) != "A" || readSlot(t, dir, Latest) != "A" {
		t.Fatalf("first snapshot: pristine/latest")
	}
	if _, err := os.Stat(filepath.Join(dir, Hour+".db")); !os.IsNotExist(err) {
		t.Fatal("hour should not exist after the first snapshot")
	}

	t1 := t0.Add(10 * time.Minute)
	if err := Rotate(dir, snap(t, "B", t1), t1); err != nil {
		t.Fatal(err)
	}
	if readSlot(t, dir, Latest) != "B" || readSlot(t, dir, Hour) != "A" {
		t.Fatalf("second snapshot latest=%s hour=%s", readSlot(t, dir, Latest), readSlot(t, dir, Hour))
	}
	if readSlot(t, dir, Pristine) != "A" {
		t.Fatal("pristine was overwritten")
	}

	t2 := t0.Add(60 * time.Minute)
	if err := Rotate(dir, snap(t, "C", t2), t2); err != nil {
		t.Fatal(err)
	}
	if readSlot(t, dir, Latest) != "C" {
		t.Fatal(readSlot(t, dir, Latest))
	}
	if readSlot(t, dir, Hour) != "B" {
		t.Fatalf("hour=%s", readSlot(t, dir, Hour))
	}
	if readSlot(t, dir, Day) != "A" {
		t.Fatalf("day=%s", readSlot(t, dir, Day))
	}
}

func TestListAndPathRejectsUnknown(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := Rotate(dir, snap(t, "A", t0), t0); err != nil {
		t.Fatal(err)
	}
	slots, err := List(dir)
	if err != nil || len(slots) != 2 {
		t.Fatalf("slots=%v err=%v", slots, err)
	}
	if _, err := Path(dir, "nope"); err == nil {
		t.Fatal("expected error")
	}
}
