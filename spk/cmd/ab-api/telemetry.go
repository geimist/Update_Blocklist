package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"autoban/internal/appdb"
)

const (
	stateTelemetryUUID = "telemetry_uuid"
	stateWorks         = "telemetry_works"
	stateWorksVersion  = "telemetry_works_version"
	stateWorksDeferred = "telemetry_works_deferred_version"
)

type telemetryView struct {
	Device           string `json:"device"`
	DSM              string `json:"dsm"`
	DSMBuild         string `json:"dsm_build"`
	Version          string `json:"version"`
	Arch             string `json:"arch"`
	UUID             string `json:"uuid"`
	Works            string `json:"works"`
	WorksVersion     string `json:"works_version"`
	Deferred         bool   `json:"deferred"`
	ShowPrompt       bool   `json:"show_prompt"`
	TelemetryEnabled bool   `json:"telemetry_enabled"`
}

var (
	telemetryUUIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	telemetryOKRe   = regexp.MustCompile(`"status"\s*:\s*"success"`)
)

func (s *server) handleTelemetry(w http.ResponseWriter, r *http.Request) {
	db, err := s.db()
	if err != nil {
		writeErr(w, err)
		return
	}
	defer db.Close()

	switch r.Method {
	case http.MethodGet:
		view, err := s.telemetrySnapshot(db)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, view)
	case http.MethodPost:
		s.postTelemetry(w, r, db)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *server) postTelemetry(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	var in struct {
		Works string `json:"works"`
		Defer bool   `json:"defer"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	version := s.packageVersion()
	if version == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing version"})
		return
	}
	if in.Works == "0" || in.Works == "1" {
		if err := s.sendWorks(db, version, in.Works); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
	} else if in.Defer {
		if err := appdb.SetState(db, stateWorksDeferred, version); err != nil {
			writeErr(w, err)
			return
		}
	} else {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "works must be 0 or 1"})
		return
	}
	view, err := s.telemetrySnapshot(db)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *server) sendWorks(db *sql.DB, version, works string) error {
	id, err := ensureTelemetryUUID(db)
	if err != nil {
		return err
	}
	device := telemetryDevice()
	arch := uname()
	if device == "" || arch == "" {
		return fmt.Errorf("missing device or arch")
	}
	endpoint, err := telemetryEndpoint(s.target)
	if err != nil {
		return err
	}
	q := telemetryQuery(telemetryFields{
		UUID: id, Device: device, DSM: fileKV("/etc.defaults/VERSION", "productversion"),
		DSMBuild: fileKV("/etc.defaults/VERSION", "buildnumber"), Version: version, Arch: arch,
	}, works)
	if err := sendTelemetry(endpoint, q); err != nil {
		return err
	}
	if err := appdb.SetState(db, stateWorks, works); err != nil {
		return err
	}
	if err := appdb.SetState(db, stateWorksVersion, version); err != nil {
		return err
	}
	return appdb.DeleteState(db, stateWorksDeferred)
}

func (s *server) telemetrySnapshot(db *sql.DB) (telemetryView, error) {
	version := s.packageVersion()
	id, err := ensureTelemetryUUID(db)
	if err != nil {
		return telemetryView{}, err
	}
	works, err := appdb.GetState(db, stateWorks)
	if err != nil {
		return telemetryView{}, err
	}
	worksVersion, err := appdb.GetState(db, stateWorksVersion)
	if err != nil {
		return telemetryView{}, err
	}
	deferredVersion, err := appdb.GetState(db, stateWorksDeferred)
	if err != nil {
		return telemetryView{}, err
	}
	enabled, err := appdb.Get(db, "telemetry_enabled")
	if err != nil {
		enabled = "0"
	}
	okRun, err := appdb.HasSuccessfulRun(db)
	if err != nil {
		return telemetryView{}, err
	}
	current := ""
	if worksVersion == version && (works == "0" || works == "1") {
		current = works
	}
	return telemetryView{
		Device:           telemetryDevice(),
		DSM:              fileKV("/etc.defaults/VERSION", "productversion"),
		DSMBuild:         fileKV("/etc.defaults/VERSION", "buildnumber"),
		Version:          version,
		Arch:             uname(),
		UUID:             id,
		Works:            current,
		WorksVersion:     worksVersion,
		Deferred:         version != "" && deferredVersion == version,
		ShowPrompt:       telemetryShowPrompt(version, works, worksVersion, deferredVersion, okRun),
		TelemetryEnabled: enabled == "1",
	}, nil
}

func telemetryShowPrompt(version, works, worksVersion, deferredVersion string, hasSuccess bool) bool {
	if version == "" || !hasSuccess {
		return false
	}
	if deferredVersion == version {
		return false
	}
	if worksVersion == version && (works == "0" || works == "1") {
		return false
	}
	return true
}

type telemetryFields struct {
	UUID, Device, DSM, DSMBuild, Version, Arch string
}

func telemetryQuery(f telemetryFields, works string) url.Values {
	q := url.Values{}
	q.Set("uuid", f.UUID)
	q.Set("device", f.Device)
	q.Set("dsm", f.DSM)
	q.Set("dsm_build", f.DSMBuild)
	q.Set("version", f.Version)
	q.Set("arch", f.Arch)
	if works == "0" || works == "1" {
		q.Set("works", works)
	}
	return q
}

func telemetryEndpoint(target string) (string, error) {
	b, err := os.ReadFile(filepath.Join(target, "share", "telemetry.json"))
	if err != nil {
		return "", fmt.Errorf("no telemetry endpoint")
	}
	var doc struct {
		Endpoint string `json:"endpoint"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return "", fmt.Errorf("no telemetry endpoint")
	}
	endpoint := strings.TrimSpace(doc.Endpoint)
	if !strings.HasPrefix(endpoint, "https://") {
		return "", fmt.Errorf("no telemetry endpoint")
	}
	return endpoint, nil
}

func sendTelemetry(endpoint string, q url.Values) error {
	req, err := http.NewRequest(http.MethodGet, endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return fmt.Errorf("telemetry rejected")
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return fmt.Errorf("telemetry redirect left https")
			}
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("telemetry rejected")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !telemetryOKRe.Match(body) {
		return fmt.Errorf("telemetry rejected")
	}
	return nil
}

func ensureTelemetryUUID(db *sql.DB) (string, error) {
	id, err := appdb.GetState(db, stateTelemetryUUID)
	if err != nil {
		return "", err
	}
	if id != "" {
		return id, nil
	}
	id, err = newTelemetryUUID()
	if err != nil {
		return "", err
	}
	if err := appdb.SetState(db, stateTelemetryUUID, id); err != nil {
		return "", err
	}
	return id, nil
}

func newTelemetryUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	id := fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
	if !telemetryUUIDRe.MatchString(id) {
		return "", fmt.Errorf("uuid")
	}
	return id, nil
}

func (s *server) packageVersion() string {
	seen := map[string]bool{}
	paths := []string{"/var/packages/AutoBan/INFO"}
	if s != nil && s.target != "" {
		paths = append(paths, filepath.Join(filepath.Dir(s.target), "INFO"))
	}
	for _, path := range paths {
		if seen[path] {
			continue
		}
		seen[path] = true
		if v := fileKV(path, "version"); v != "" {
			return v
		}
	}
	return ""
}

func fileKV(path, key string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	prefix := key + `="`
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, prefix) && strings.HasSuffix(line, `"`) && len(line) > len(prefix) {
			return line[len(prefix) : len(line)-1]
		}
	}
	return ""
}

func telemetryDevice() string {
	if path, err := exec.LookPath("synogetkeyvalue"); err == nil {
		out, err := exec.Command(path, "/etc.defaults/synoinfo.conf", "upnpmodelname").Output()
		if err == nil {
			model := stripSpace(string(out))
			if model != "" {
				return model
			}
		}
	}
	b, err := os.ReadFile("/proc/sys/kernel/syno_hw_version")
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(stripSpace(string(b)), "-j")
}

func stripSpace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}
