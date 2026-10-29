// Package backup keeps time-stretched copies of the DSM auto-block database.
//
// Slots: pristine (once), latest (every run), then hour / day / week / month.
// A slot is replaced only when it is empty or older than its period. The
// displaced copy cascades into the next wider slot, so a 10-minute schedule
// still retains roughly 1h, 1d, 7d and 30d of history.
package backup

import (
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	Pristine = "pristine"
	Latest   = "latest"
	Hour     = "hour"
	Day      = "day"
	Week     = "week"
	Month    = "month"
)

var slots = []string{Pristine, Latest, Hour, Day, Week, Month}

type tier struct {
	name   string
	period time.Duration
}

var cascade = []tier{
	{Hour, time.Hour},
	{Day, 24 * time.Hour},
	{Week, 7 * 24 * time.Hour},
	{Month, 30 * 24 * time.Hour},
}

// Rotate stores fresh as the newest snapshot and updates wider slots.
// fresh must already be a consistent database file. pristine is written
// only when it does not exist yet.
func Rotate(dir, fresh string, now time.Time) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	pristine := filepath.Join(dir, Pristine+".db")
	if _, err := os.Stat(pristine); errors.Is(err, os.ErrNotExist) {
		if err := copyFile(fresh, pristine); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	latest := filepath.Join(dir, Latest+".db")
	var displaced []byte
	var displacedAt time.Time
	if st, err := os.Stat(latest); err == nil {
		displaced, err = os.ReadFile(latest)
		if err != nil {
			return err
		}
		displacedAt = st.ModTime()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := copyFile(fresh, latest); err != nil {
		return err
	}

	for _, t := range cascade {
		if displaced == nil {
			break
		}
		slot := filepath.Join(dir, t.name+".db")
		st, err := os.Stat(slot)
		missing := errors.Is(err, os.ErrNotExist)
		if err != nil && !missing {
			return err
		}
		due := missing || now.Sub(st.ModTime()) >= t.period
		if !due {
			break
		}
		var next []byte
		var nextAt time.Time
		if !missing {
			next, err = os.ReadFile(slot)
			if err != nil {
				return err
			}
			nextAt = st.ModTime()
		}
		if err := writeFileWithTime(slot, displaced, displacedAt); err != nil {
			return err
		}
		if next == nil {
			displaced = nil
		} else {
			displaced = next
			displacedAt = nextAt
		}
	}
	return nil
}

// Slot describes one backup file that currently exists.
type Slot struct {
	Name    string
	ModTime time.Time
	Bytes   int64
}

// List returns existing slots in display order.
// Die Aufnahmezeit steht in der Datei (autoban_taken) oder in slots.mtime.
// Die Dateizeit allein reicht nicht: Hyper Backup setzt sie auf 1970 zurück.
func List(dir string) ([]Slot, error) {
	noted := readSidecar(dir)
	var out []Slot
	for _, name := range slots {
		path := filepath.Join(dir, name+".db")
		st, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		when := st.ModTime()
		if at := takenUnix(path); at > 0 {
			when = time.Unix(at, 0)
		} else if at := noted[name]; at > 0 {
			when = time.Unix(at, 0)
		}
		out = append(out, Slot{Name: name, ModTime: when, Bytes: st.Size()})
	}
	return out, nil
}

func takenUnix(path string) int64 {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return 0
	}
	defer db.Close()
	var at int64
	if err := db.QueryRow(`SELECT at FROM autoban_taken LIMIT 1`).Scan(&at); err != nil || at <= 0 {
		return 0
	}
	return at
}

func readSidecar(dir string) map[string]int64 {
	b, err := os.ReadFile(filepath.Join(dir, "slots.mtime"))
	if err != nil {
		return nil
	}
	out := map[string]int64{}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		n, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || n <= 0 {
			continue
		}
		out[fields[0]] = n
	}
	return out
}

// Path returns the file for a known slot name.
func Path(dir, name string) (string, error) {
	switch name {
	case Pristine, Latest, Hour, Day, Week, Month:
	default:
		return "", errors.New("unknown backup slot")
	}
	p := filepath.Join(dir, name+".db")
	if _, err := os.Stat(p); err != nil {
		return "", err
	}
	return p, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chtimes(tmp, st.ModTime(), st.ModTime()); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

func writeFileWithTime(path string, data []byte, when time.Time) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Chtimes(tmp, when, when); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
