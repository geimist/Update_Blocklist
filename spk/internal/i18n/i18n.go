// Package i18n resolves the DSM display language the same way synOCR's language() does.
// The GUI catalogue is lang_<code>.json, one file per DSM language.
// Notification sentences live in ui/texts/<code>/strings (msg_import_failed, msg_import_recovered).
package i18n

import (
	"encoding/json"
	"os"
	"strings"
)

var isoToSyno = map[string]string{
	"de": "ger", "en": "enu", "zh": "chs", "cs": "csy", "jp": "jpn", "ko": "krn",
	"da": "dan", "fr": "fre", "it": "ita", "nl": "nld", "no": "nor", "pl": "plk",
	"ru": "rus", "sp": "spn", "sv": "sve", "hu": "hun", "tr": "trk", "pt": "ptg",
}

const fallback = "ger"

// Resolve picks a Synology 3-letter language code.
// Priority: personal DSM language, DSM language, browser language when DSM is "def", then ger.
func Resolve(personal, dsmLang, acceptLanguage string) string {
	lang := strings.TrimSpace(dsmLang)
	if lang == "" {
		lang = "def"
	}
	if lang == "def" {
		lang = browserLang(acceptLanguage)
	}
	p := strings.TrimSpace(personal)
	if p != "" && p != "def" && p != "null" {
		lang = p
	}
	if lang == "" || lang == "def" {
		return fallback
	}
	return lang
}

func browserLang(accept string) string {
	if accept == "" {
		return fallback
	}
	first := accept
	if i := strings.IndexAny(first, ",;"); i >= 0 {
		first = first[:i]
	}
	first = strings.TrimSpace(first)
	if len(first) >= 2 {
		code := strings.ToLower(first[:2])
		if syn, ok := isoToSyno[code]; ok {
			return syn
		}
	}
	return fallback
}

// DSMLanguage reads language= from synoinfo.conf. Missing file yields "def".
func DSMLanguage(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "def"
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "language=") {
			continue
		}
		v := strings.Trim(strings.TrimPrefix(line, "language="), `"`)
		if len(v) >= 3 {
			return v[:3]
		}
		return v
	}
	return "def"
}

// PersonalLanguage reads .Personal.lang from a DSM usersettings file.
func PersonalLanguage(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var doc struct {
		Personal struct {
			Lang string `json:"lang"`
		} `json:"Personal"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return ""
	}
	return doc.Personal.Lang
}
