package sysdb

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInsertCountExportDelete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "block.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	added, err := InsertBatch(db, []string{"1.2.3.4", "999.1.1.1", "10.0.0.1", "1.2.3.4"}, 100, 0, 1, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if added != 2 {
		t.Fatalf("added=%d", added)
	}
	n, err := Count(db)
	if err != nil || n != 2 {
		t.Fatalf("count=%d err=%v", n, err)
	}
	var buf strings.Builder
	if err := ExportDeny(db, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "1.2.3.4") || strings.Contains(buf.String(), "999") {
		t.Fatalf("export %q", buf.String())
	}
	if _, err := db.Exec(`UPDATE AutoBlockIP SET ExpireTime=50 WHERE IP='10.0.0.1'`); err != nil {
		t.Fatal(err)
	}
	gone, err := DeleteExpired(db, 100)
	if err != nil || gone != 1 {
		t.Fatalf("gone=%d err=%v", gone, err)
	}
}

func TestBackupAndRestore(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "live.db")
	bak := filepath.Join(dir, "bak")
	db, err := Open(src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InsertBatch(db, []string{"8.8.8.8"}, 1, 0, 1, 0, ""); err != nil {
		t.Fatal(err)
	}
	db.Close()
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	if err := Backup(src, bak, now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(bak, "pristine.db")); err != nil {
		t.Fatal(err)
	}
	db, err = Open(src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InsertBatch(db, []string{"9.9.9.9"}, 1, 0, 1, 0, ""); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if err := RestoreFile(filepath.Join(bak, "pristine.db"), src); err != nil {
		t.Fatal(err)
	}
	db, err = Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	n, err := Count(db)
	if err != nil || n != 1 {
		t.Fatalf("after restore count=%d err=%v", n, err)
	}
}

func TestIPStd(t *testing.T) {
	if got := IPStd("1.2.3.4"); got != "0000:0000:0000:0000:0000:FFFF:0102:0304" {
		t.Fatal(got)
	}
}

func TestCanonicalIPv6(t *testing.T) {
	ip, std, ok := Canonical("2001:4451:03F7:C400:184F:4CDB:AA37:50ED")
	if !ok || ip != "2001:4451:3f7:c400:184f:4cdb:aa37:50ed" || std != "2001:4451:03F7:C400:184F:4CDB:AA37:50ED" {
		t.Fatalf("got %v %s %s", ok, ip, std)
	}
	ip, std, ok = Canonical("::ffff:1.2.3.4")
	if !ok || ip != "1.2.3.4" || std != "0000:0000:0000:0000:0000:FFFF:0102:0304" {
		t.Fatalf("mapped %v %s %s", ok, ip, std)
	}
	if _, _, ok = Canonical("fe80::1%eth0"); ok {
		t.Fatal("zone id accepted")
	}
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "block.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	added, err := InsertBatch(db, []string{"2001:DB8::1", "::ffff:8.8.8.8"}, 1, 0, 1, 0, "")
	if err != nil || added != 2 {
		t.Fatalf("added=%d err=%v", added, err)
	}
	var stored, storedStd string
	if err := db.QueryRow(`SELECT IP, IPStd FROM AutoBlockIP WHERE IP=?`, "2001:db8::1").Scan(&stored, &storedStd); err != nil {
		t.Fatal(err)
	}
	if storedStd != "2001:0DB8:0000:0000:0000:0000:0000:0001" {
		t.Fatal(storedStd)
	}
}
