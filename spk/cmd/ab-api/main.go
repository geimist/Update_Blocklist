// ab-api serves the AutoBan DSM UI and its JSON endpoints.
//
// Die Binary ist wegen modernc.org/sqlite (~10 MB/Arch) bewusst größer als der
// C-Helper. Begründung und mögliche spätere Verschlankung: siehe
// package appdb.
package main

import (
	"archive/zip"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cgi"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"autoban/internal/appdb"
	"autoban/internal/backup"
	"autoban/internal/i18n"
)

type server struct {
	ui     string
	varDir string
	target string
	helper string
	sysDB  string
	tmp    string
	backup string
}

func main() {
	s := newServer()
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.route)
	if len(os.Args) >= 3 && os.Args[1] == "-http" {
		_ = os.Setenv("AUTOBAN_SKIP_AUTH", "1")
		if err := http.ListenAndServe(os.Args[2], mux); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := cgi.Serve(mux); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newServer() *server {
	s := &server{
		varDir: "/var/packages/AutoBan/var",
		target: "/var/packages/AutoBan/target",
		sysDB:  "/etc/synoautoblock.db",
	}
	if root := os.Getenv("AUTOBAN_ROOT"); root != "" {
		s.varDir = filepath.Join(root, "var")
		s.target = filepath.Join(root, "target")
		if v := os.Getenv("AUTOBAN_SYSDB"); v != "" {
			s.sysDB = v
		} else {
			s.sysDB = filepath.Join(s.varDir, "sys.db")
		}
	}
	if v := os.Getenv("AUTOBAN_UI"); v != "" {
		s.ui = v
	} else if exe, err := os.Executable(); err == nil {
		s.ui = filepath.Clean(filepath.Join(filepath.Dir(exe), "../../ui"))
	}
	s.backup = filepath.Join(s.varDir, "db_backups")
	s.tmp = filepath.Join(s.varDir, "tmp")
	s.helper = os.Getenv("AUTOBAN_HELPER")
	if s.helper == "" {
		s.helper = filepath.Join(s.target, "bin", "helper", helperName())
	}
	return s
}

func helperName() string {
	switch m := strings.ToLower(uname()); m {
	case "i686", "i386":
		return "ab-helper-i686"
	case "aarch64", "arm64":
		return "ab-helper-aarch64"
	case "armv7l", "armv6l":
		return "ab-helper-armv7"
	default:
		if strings.HasPrefix(m, "armv7") {
			return "ab-helper-armv7"
		}
		return "ab-helper-x86_64"
	}
}

func uname() string {
	out, err := exec.Command("uname", "-m").Output()
	if err != nil {
		return "x86_64"
	}
	return strings.TrimSpace(string(out))
}

func (s *server) route(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	if action == "" && strings.HasPrefix(r.URL.Path, "/api/") {
		action = strings.TrimPrefix(r.URL.Path, "/api/")
	}
	if !authorized() {
		if action == "" {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "access denied"})
		return
	}
	if action == "" {
		s.static(w, r)
		return
	}
	switch action {
	case "i18n":
		s.handleI18n(w, r)
	case "settings":
		s.handleSettings(w, r)
	case "stats":
		s.handleStats(w, r)
	case "history":
		s.handleHistory(w, r)
	case "status":
		s.handleStatus(w, r)
	case "log":
		s.handleLog(w, r)
	case "backups":
		s.handleBackups(w, r)
	case "run":
		s.handleRun(w, r)
	case "restore":
		s.handleRestore(w, r)
	case "clear":
		s.handleClear(w, r)
	case "support":
		s.handleSupport(w, r)
	default:
		http.NotFound(w, r)
	}
}

func authorized() bool {
	if os.Getenv("AUTOBAN_SKIP_AUTH") == "1" {
		return true
	}
	cgiPath := "/usr/syno/synoman/webman/login.cgi"
	if _, err := os.Stat(cgiPath); err != nil {
		return false
	}
	cmd := exec.Command(cgiPath)
	cmd.Env = loginCGIEnv(os.Environ())
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return false
	}
	return loginSuccess(string(out))
}

// login.cgi liest die DSM-Sitzung aus dem Cookie. Bei POST wertet sie sie nicht aus,
// deshalb wie in synOCR vorher auf GET stellen und den Request-Body abhängen.
func loginCGIEnv(env []string) []string {
	out := make([]string, 0, len(env)+1)
	sawMethod := false
	for _, e := range env {
		switch {
		case strings.HasPrefix(e, "REQUEST_METHOD="):
			out = append(out, "REQUEST_METHOD=GET")
			sawMethod = true
		case strings.HasPrefix(e, "CONTENT_LENGTH="), strings.HasPrefix(e, "CONTENT_TYPE="):
			continue
		default:
			out = append(out, e)
		}
	}
	if !sawMethod {
		out = append(out, "REQUEST_METHOD=GET")
	}
	return out
}

func loginSuccess(text string) bool {
	compact := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\n', '\r', '\t':
			return -1
		default:
			return r
		}
	}, text)
	if strings.Contains(compact, `"success":false`) {
		return false
	}
	return strings.Contains(compact, `"success":true`)
}

func (s *server) static(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/")
	// DSM ruft /webman/3rdparty/AutoBan/index.cgi auf. Der iframe bekommt damit die Oberfläche.
	if name == "" || name == "index.cgi" || strings.HasSuffix(name, "/index.cgi") {
		name = "index.html"
	}
	if strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFile(w, r, filepath.Join(s.ui, name))
}

func (s *server) db() (*sql.DB, error) {
	if err := os.MkdirAll(s.varDir, 0o755); err != nil {
		return nil, err
	}
	return appdb.Open(filepath.Join(s.varDir, "app.db"))
}

func (s *server) handleI18n(w http.ResponseWriter, r *http.Request) {
	user := firstEnv("login_user", "AUTOBAN_USER", "REMOTE_USER")
	personal := ""
	if user != "" {
		personal = i18n.PersonalLanguage(filepath.Join("/usr/syno/etc/preference", user, "usersettings"))
	}
	code := i18n.Resolve(personal, i18n.DSMLanguage("/etc/synoinfo.conf"), r.Header.Get("Accept-Language"))
	used, stringsMap := loadLang(s.ui, code)
	writeJSON(w, http.StatusOK, map[string]any{"lang": used, "strings": stringsMap})
}

func loadLang(ui, code string) (string, map[string]string) {
	read := func(name string) map[string]string {
		b, err := os.ReadFile(filepath.Join(ui, "lang", name))
		if err != nil {
			return nil
		}
		var m map[string]string
		if json.Unmarshal(b, &m) != nil {
			return nil
		}
		return m
	}
	if m := read("lang_" + code + ".json"); m != nil {
		return code, m
	}
	if m := read("lang_ger.json"); m != nil {
		return "ger", m
	}
	return "ger", map[string]string{}
}

func (s *server) handleSettings(w http.ResponseWriter, r *http.Request) {
	db, err := s.db()
	if err != nil {
		writeErr(w, err)
		return
	}
	defer db.Close()
	if r.Method == http.MethodGet {
		vals, err := appdb.Settings(db)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, vals)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in map[string]string
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, err)
		return
	}
	clean, err := validateSettings(in)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := appdb.SetSettings(db, clean); err != nil {
		writeErr(w, err)
		return
	}
	if clean["scheduler_enabled"] == "0" {
		// Laufenden Import abbrechen, damit keine Quelle mehr abgefragt wird.
		killPidFile(filepath.Join(s.varDir, "run.pid"), "update_blocklist")
	}
	_ = os.WriteFile(filepath.Join(s.varDir, "scheduler.reload"), []byte("1\n"), 0o644)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *server) handleStats(w http.ResponseWriter, r *http.Request) {
	db, err := s.db()
	if err != nil {
		writeErr(w, err)
		return
	}
	defer db.Close()
	runs, err := appdb.Runs(db, 50)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": runs})
}

func (s *server) handleHistory(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("days")
	span := 30
	if raw != "" {
		span, _ = strconv.Atoi(raw)
	}
	db, err := s.db()
	if err != nil {
		writeErr(w, err)
		return
	}
	defer db.Close()
	if err := appdb.FoldDays(db); err != nil {
		writeErr(w, err)
		return
	}
	points, err := appdb.Days(db, span)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"days": points})
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	running := pidAlive(filepath.Join(s.varDir, "run.pid"), "update_blocklist")
	// Der Scheduler-Prozess läuft mit dem Paket weiter und überspringt Läufe,
	// wenn die Einstellung aus ist. Die Anzeige folgt der Einstellung.
	enabled := false
	if db, err := s.db(); err == nil {
		if vals, err := appdb.Settings(db); err == nil {
			enabled = vals["scheduler_enabled"] == "1"
		}
		_ = db.Close()
	}
	scheduler := enabled && pidAlive(filepath.Join(s.varDir, "scheduler.pid"), "autoban-scheduler")
	writeJSON(w, http.StatusOK, map[string]bool{"running": running, "scheduler": scheduler})
}

func (s *server) handleLog(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(s.varDir, "log", "autoban.log")
	if r.Method == http.MethodPost {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			writeErr(w, err)
			return
		}
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		b = nil
	}
	writeJSON(w, http.StatusOK, map[string]string{"text": string(b)})
}

func (s *server) handleBackups(w http.ResponseWriter, r *http.Request) {
	slots, err := backup.List(s.backup)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"slots": []any{}})
		return
	}
	type item struct {
		Name  string `json:"name"`
		Unix  int64  `json:"unix"`
		Bytes int64  `json:"bytes"`
	}
	out := make([]item, 0, len(slots))
	for _, sl := range slots {
		out = append(out, item{Name: sl.Name, Unix: sl.ModTime.Unix(), Bytes: sl.Bytes})
	}
	writeJSON(w, http.StatusOK, map[string]any{"slots": out})
}

func (s *server) handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if pidAlive(filepath.Join(s.varDir, "run.pid"), "update_blocklist") {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "busy"})
		return
	}
	script := filepath.Join(s.target, "bin", "update_blocklist.sh")
	if _, err := os.Stat(script); err != nil {
		script = os.Getenv("AUTOBAN_SCRIPT")
	}
	if script == "" {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "script missing"})
		return
	}
	cmd := exec.Command(script)
	cmd.Env = os.Environ()
	if err := cmd.Start(); err != nil {
		writeErr(w, err)
		return
	}
	go func() { _ = cmd.Wait() }()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *server) handleSupport(w http.ResponseWriter, r *http.Request) {
	out, err := os.CreateTemp("", "autoban-support-*.zip")
	if err != nil {
		writeErr(w, err)
		return
	}
	name := out.Name()
	defer os.Remove(name)
	zw := zip.NewWriter(out)
	if err := s.writeSupportZip(zw); err != nil {
		zw.Close()
		out.Close()
		writeErr(w, err)
		return
	}
	if err := zw.Close(); err != nil {
		out.Close()
		writeErr(w, err)
		return
	}
	if _, err := out.Seek(0, io.SeekStart); err != nil {
		out.Close()
		writeErr(w, err)
		return
	}
	st, err := out.Stat()
	if err != nil {
		out.Close()
		writeErr(w, err)
		return
	}
	filename := "AutoBan-support-" + time.Now().Format("20060102-150405") + ".zip"
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
	_, _ = io.Copy(w, out)
	out.Close()
}

func (s *server) writeSupportZip(zw *zip.Writer) error {
	snap, err := s.snapshotAppDB()
	if err != nil {
		return err
	}
	defer os.Remove(snap)
	if err := addZipFile(zw, "app.db", snap); err != nil {
		return err
	}
	if err := s.addSupportSysDB(zw); err != nil {
		return err
	}
	logDir := filepath.Join(s.varDir, "log")
	entries, _ := os.ReadDir(logDir)
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		path := filepath.Join(logDir, ent.Name())
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if err := addZipFile(zw, filepath.ToSlash(filepath.Join("log", ent.Name())), path); err != nil {
			return err
		}
	}
	const pkgLog = "/var/log/packages/AutoBan.log"
	if info, err := os.Lstat(pkgLog); err == nil && info.Mode().IsRegular() {
		if err := addZipFile(zw, "AutoBan.log", pkgLog); err != nil {
			if err := addZipBytes(zw, "AutoBan.log.unavailable.txt", []byte("AutoBan.log was not readable (/var/log/packages/AutoBan.log).\n")); err != nil {
				return err
			}
		}
	} else {
		if err := addZipBytes(zw, "AutoBan.log.unavailable.txt", []byte("AutoBan.log was not readable (/var/log/packages/AutoBan.log).\n")); err != nil {
			return err
		}
	}
	return nil
}

func (s *server) addSupportSysDB(zw *zip.Writer) error {
	dest := filepath.Join(s.tmp, "support-sys.db")
	cmd := s.helperCmd("export-db")
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := fmt.Sprintf("synoautoblock.db was not exported (%s).\n%s", s.sysDB, out)
		return addZipBytes(zw, "synoautoblock.db.unavailable.txt", []byte(msg))
	}
	defer os.Remove(dest)
	if err := addZipFile(zw, "synoautoblock.db", dest); err != nil {
		msg := fmt.Sprintf("synoautoblock.db was not readable (%s).\n", dest)
		return addZipBytes(zw, "synoautoblock.db.unavailable.txt", []byte(msg))
	}
	return nil
}

func (s *server) snapshotAppDB() (string, error) {
	f, err := os.CreateTemp("", "autoban-appdb-*.db")
	if err != nil {
		return "", err
	}
	path := f.Name()
	f.Close()
	os.Remove(path)
	db, err := s.db()
	if err != nil {
		return "", err
	}
	defer db.Close()
	quoted := strings.ReplaceAll(path, "'", "''")
	if _, err := db.Exec("VACUUM INTO '" + quoted + "'"); err != nil {
		src, rerr := os.Open(filepath.Join(s.varDir, "app.db"))
		if rerr != nil {
			return "", err
		}
		defer src.Close()
		dst, rerr := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if rerr != nil {
			return "", rerr
		}
		_, rerr = io.Copy(dst, src)
		dst.Close()
		if rerr != nil {
			os.Remove(path)
			return "", rerr
		}
	}
	return path, nil
}

func addZipFile(zw *zip.Writer, name, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	hdr, err := zip.FileInfoHeader(st)
	if err != nil {
		return err
	}
	hdr.Name = name
	hdr.Method = zip.Deflate
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, f)
	return err
}

func addZipBytes(zw *zip.Writer, name string, b []byte) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func (s *server) handleRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Slot string `json:"slot"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeErr(w, err)
		return
	}
	if _, err := backup.Path(s.backup, body.Slot); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown slot"})
		return
	}
	if err := s.helperCmd("restore", body.Slot).Run(); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *server) handleClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if pidAlive(filepath.Join(s.varDir, "run.pid"), "update_blocklist") {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "busy"})
		return
	}
	out, err := s.helperCmd("clear-blocklist").Output()
	if err != nil {
		writeErr(w, err)
		return
	}
	removed, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		writeErr(w, err)
		return
	}
	s.noteCleared(removed)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": removed})
}

func (s *server) noteCleared(removed int64) {
	path := filepath.Join(s.varDir, "log", "autoban.log")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	line := time.Now().Format("2006-01-02 15:04:05") + " INFO Blockliste geleert (" + strconv.FormatInt(removed, 10) + ")\n"
	_, _ = f.WriteString(line)
}

func (s *server) helperCmd(args ...string) *exec.Cmd {
	full := []string{"--db", s.sysDB, "--backup-dir", s.backup, "--tmp-dir", s.tmp}
	full = append(full, args...)
	return exec.Command(s.helper, full...)
}

func pidAlive(path, needle string) bool {
	_, pid := processFromPidFile(path)
	if pid <= 0 {
		return false
	}
	if _, err := os.Stat("/proc"); err != nil {
		err = syscall.Kill(pid, 0)
		return err == nil || err == syscall.EPERM
	}
	dir := "/proc/" + strconv.Itoa(pid)
	if _, err := os.Stat(dir); err != nil {
		return false
	}
	cmd, err := os.ReadFile(dir + "/cmdline")
	if err != nil || len(cmd) == 0 || needle == "" {
		return true
	}
	flat := strings.ReplaceAll(string(cmd), "\x00", " ")
	return strings.Contains(flat, needle)
}

func killPidFile(path, needle string) {
	if !pidAlive(path, needle) {
		return
	}
	proc, _ := processFromPidFile(path)
	if proc == nil {
		return
	}
	_ = proc.Signal(syscall.SIGTERM)
}

func processFromPidFile(path string) (*os.Process, int) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return nil, 0
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil, 0
	}
	return proc, pid
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}
