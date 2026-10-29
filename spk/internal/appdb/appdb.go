// Package appdb speichert Einstellungen, Zustand und Laufstatistik von AutoBan.
//
// Größenkompromiss: modernc.org/sqlite ist in ab-api eingebettet (~10 MB pro
// Architektur). Das Hauptskript und ab-helper nutzen bereits das DSM-sqlite3.
// Wir behalten die Go-Bibliothek vorerst, weil die CGI-Schicht damit
// Transaktionen, Prepared Statements und Schema-Embed ohne SQL-Escaping und
// ohne Prozess-Spawn pro Request bekommt – Auth/Validierung/JSON bleiben in Go
// und die App-DB-Anbindung bleibt robust. Geschwindigkeit der GUI spielt keine
// Rolle; spürbar ist nur die Binary-/SPK-Größe. Später möglich: modernc
// zugunsten von DSM-sqlite3 ersetzen und Go als CGI behalten.
package appdb

import (
	"database/sql"
	_ "embed"
	"fmt"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

type Run struct {
	ID          int64  `json:"id"`
	StartedAt   int64  `json:"started_at"`
	DurationMs  int64  `json:"duration_ms"`
	OnlineCount int    `json:"online_count"`
	Diffs       int    `json:"diffs"`
	Added       int    `json:"added"`
	Expired     int    `json:"expired"`
	GeoIPSkip   int    `json:"geoip_skip"`
	CountBefore int    `json:"count_before"`
	CountAfter  int    `json:"count_after"`
	Status      string `json:"status"`
	Message     string `json:"message"`
}

func Open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func Settings(db *sql.DB) (map[string]string, error) {
	rows, err := db.Query(`SELECT key, value FROM settings ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

func SetSettings(db *sql.DB, values map[string]string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO settings(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	for k, v := range values {
		if _, err := stmt.Exec(k, v); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func State(db *sql.DB) (map[string]string, error) {
	rows, err := db.Query(`SELECT key, value FROM state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

func Runs(db *sql.DB, limit int) ([]Run, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := db.Query(`SELECT id, started_at, duration_ms, online_count, diffs, added,
		expired, geoip_skip, count_before, count_after, status, message
		FROM runs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		var r Run
		if err := rows.Scan(&r.ID, &r.StartedAt, &r.DurationMs, &r.OnlineCount, &r.Diffs,
			&r.Added, &r.Expired, &r.GeoIPSkip, &r.CountBefore, &r.CountAfter, &r.Status, &r.Message); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if out == nil {
		out = []Run{}
	}
	return out, rows.Err()
}

func InsertRun(db *sql.DB, r Run) error {
	_, err := db.Exec(`INSERT INTO runs(started_at, duration_ms, online_count, diffs, added,
		expired, geoip_skip, count_before, count_after, status, message)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		r.StartedAt, r.DurationMs, r.OnlineCount, r.Diffs, r.Added, r.Expired,
		r.GeoIPSkip, r.CountBefore, r.CountAfter, r.Status, r.Message)
	if err != nil {
		return err
	}
	return FoldDays(db)
}

// FoldDays schreibt jeden Tag, der noch Einzelläufe hat, nach run_days:
// Bestand und Listengröße als letzter Wert, hinzugefügte Adressen als Summe.
// Einzelläufe von heute und gestern bleiben in runs, damit die Laufliste echt bleibt.
func FoldDays(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`
INSERT INTO run_days(day, online_count, added, count_after)
SELECT day, online_count, added_sum, count_after
FROM (
  SELECT date(started_at, 'unixepoch', 'localtime') AS day,
         SUM(added) OVER (PARTITION BY date(started_at, 'unixepoch', 'localtime')) AS added_sum,
         online_count,
         count_after,
         ROW_NUMBER() OVER (
           PARTITION BY date(started_at, 'unixepoch', 'localtime')
           ORDER BY started_at DESC, id DESC
         ) AS rn
  FROM runs
)
WHERE rn = 1
ON CONFLICT(day) DO UPDATE SET
  online_count = excluded.online_count,
  count_after = excluded.count_after,
  added = excluded.added`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM runs WHERE started_at < strftime('%s','now','localtime','start of day','utc','-1 day')`); err != nil {
		return err
	}
	return tx.Commit()
}

// DayPoint is one chart column.
type DayPoint struct {
	Day    string `json:"day"`
	Online int    `json:"online"`
	Added  int    `json:"added"`
	Total  int    `json:"total"`
}

// Days returns daily points. span <= 0 means the whole history.
func Days(db *sql.DB, span int) ([]DayPoint, error) {
	query := `
SELECT day, online_count, added, count_after
FROM run_days
ORDER BY day ASC`
	args := []any{}
	if span > 0 {
		query = `
SELECT day, online_count, added, count_after
FROM run_days
WHERE day >= date('now','localtime', ?)
ORDER BY day ASC`
		args = append(args, fmt.Sprintf("-%d days", span))
	}
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DayPoint
	for rows.Next() {
		var p DayPoint
		if err := rows.Scan(&p.Day, &p.Online, &p.Added, &p.Total); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if out == nil {
		out = []DayPoint{}
	}
	return out, rows.Err()
}

func Get(db *sql.DB, key string) (string, error) {
	var v string
	err := db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("missing setting %s", key)
	}
	return v, err
}
