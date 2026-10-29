// Package sysdb is the only code that writes the DSM auto-block database.
package sysdb

import (
	"database/sql"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"autoban/internal/backup"

	_ "modernc.org/sqlite"
)

const createTable = `CREATE TABLE IF NOT EXISTS AutoBlockIP(
  IP varchar(50) PRIMARY KEY,
  RecordTime date NOT NULL,
  ExpireTime date NOT NULL,
  Deny boolean NOT NULL,
  IPStd varchar(50) NOT NULL,
  Type INTEGER,
  Meta varchar(256)
)`

// Open opens the system database, creating the file and table when missing.
func Open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(createTable); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func dsn(path string) string {
	return "file:" + path + "?_pragma=busy_timeout(5000)"
}

// Snapshot writes a consistent copy of src to dst.
func Snapshot(src, dst string) error {
	if _, err := os.Stat(src); err != nil {
		return err
	}
	tmp := dst + ".partial"
	_ = os.Remove(tmp)
	db, err := sql.Open("sqlite", dsn(src))
	if err != nil {
		return err
	}
	defer db.Close()
	esc := strings.ReplaceAll(tmp, "'", "''")
	if _, err = db.Exec("VACUUM INTO '" + esc + "'"); err != nil {
		if err2 := copyFile(src, tmp); err2 != nil {
			return err
		}
	}
	return os.Rename(tmp, dst)
}

// Count returns Deny=1 rows, matching the historical script.
func Count(db *sql.DB) (int, error) {
	var n int
	err := db.QueryRow(`SELECT count(IP) FROM AutoBlockIP WHERE Deny='1'`).Scan(&n)
	return n, err
}

// ExportDeny writes one Deny=1 IP per line.
func ExportDeny(db *sql.DB, w io.Writer) error {
	rows, err := db.Query(`SELECT IP FROM AutoBlockIP WHERE Deny='1' ORDER BY IP ASC`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return err
		}
		if _, err := io.WriteString(w, ip+"\n"); err != nil {
			return err
		}
	}
	return rows.Err()
}

// DeleteExpired removes Deny=1 rows whose expiry is set and already passed.
func DeleteExpired(db *sql.DB, unixNow int64) (int64, error) {
	res, err := db.Exec(
		`DELETE FROM AutoBlockIP WHERE ExpireTime <= ? AND Deny='1' AND ExpireTime != '0'`,
		unixNow,
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// InsertBatch inserts host addresses. Invalid lines are skipped.
// IPv4-mapped IPv6 is stored as IPv4. added counts newly inserted rows.
func InsertBatch(db *sql.DB, ips []string, record, expire int64, deny, typ int, meta string) (int, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO AutoBlockIP
		(IP, RecordTime, ExpireTime, Deny, IPStd, Type, Meta)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	defer stmt.Close()
	added := 0
	for _, raw := range ips {
		ip, std, ok := Canonical(raw)
		if !ok {
			continue
		}
		res, err := stmt.Exec(ip, record, expire, deny, std, typ, meta)
		if err != nil {
			tx.Rollback()
			return 0, err
		}
		n, _ := res.RowsAffected()
		added += int(n)
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return added, nil
}

// ValidIPv4 reports whether s is a dotted IPv4 address.
func ValidIPv4(s string) bool {
	if strings.Contains(s, ":") {
		return false
	}
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

// IPStd is the firewall form stored beside IP.
// IPv4 uses the mapped address. IPv6 uses eight uppercase groups.
func IPStd(ip string) string {
	_, std, ok := Canonical(ip)
	if !ok {
		return ""
	}
	return std
}

// Canonical returns the IP column and IPStd for one host address.
// IPv6 is lowercase RFC 5952. An IPv4-mapped address is returned as IPv4.
func Canonical(s string) (ip, std string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, "% \t/") {
		return "", "", false
	}
	if !strings.Contains(s, ":") {
		text, fine := plainV4(s)
		if !fine {
			return "", "", false
		}
		return text, stdV4(text), true
	}
	parsed := net.ParseIP(s)
	if parsed == nil {
		return "", "", false
	}
	if v4 := parsed.To4(); v4 != nil {
		text := v4.String()
		return text, stdV4(text), true
	}
	p := parsed.To16()
	if p == nil {
		return "", "", false
	}
	std = fmt.Sprintf("%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X",
		p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
		p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15])
	return parsed.String(), std, true
}

func plainV4(s string) (string, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return "", false
	}
	var o [4]int
	for i, p := range parts {
		if p == "" || len(p) > 3 {
			return "", false
		}
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return "", false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return "", false
		}
		o[i] = n
	}
	return fmt.Sprintf("%d.%d.%d.%d", o[0], o[1], o[2], o[3]), true
}

func stdV4(ip string) string {
	var o [4]int
	fmt.Sscanf(ip, "%d.%d.%d.%d", &o[0], &o[1], &o[2], &o[3])
	return fmt.Sprintf("0000:0000:0000:0000:0000:FFFF:%02X%02X:%02X%02X", o[0], o[1], o[2], o[3])
}

// RestoreFile replaces dst with a snapshot, removing WAL sidecars.
func RestoreFile(src, dst string) error {
	tmp := dst + ".restore"
	if err := copyFile(src, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	os.Remove(dst + "-wal")
	os.Remove(dst + "-shm")
	return nil
}

// Backup copies src into dir using the time-stretched rotation.
func Backup(src, dir string, now time.Time) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "incoming-*.db")
	if err != nil {
		return err
	}
	name := tmp.Name()
	tmp.Close()
	_ = os.Remove(name)
	if err := Snapshot(src, name); err != nil {
		os.Remove(name)
		return err
	}
	defer os.Remove(name)
	if err := os.Chtimes(name, now, now); err != nil {
		return err
	}
	return backup.Rotate(dir, name, now)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
