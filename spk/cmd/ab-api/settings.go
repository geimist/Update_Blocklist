package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

var blocklistTypes = map[string]bool{
	"all": true, "ssh": true, "mail": true, "apache": true, "imap": true,
	"ftp": true, "sip": true, "bots": true, "strongips": true, "ircbot": true,
	"bruteforcelogin": true,
}

var notifyLangs = map[string]bool{
	"ger": true, "enu": true, "fre": true, "ita": true, "spn": true, "nld": true,
	"rus": true, "plk": true, "csy": true, "hun": true, "ptg": true, "ptb": true,
	"dan": true, "nor": true, "sve": true, "trk": true, "chs": true, "cht": true,
	"jpn": true, "krn": true,
}

var intervalSteps = map[string]bool{
	"1": true, "5": true, "10": true, "15": true, "20": true, "30": true, "60": true, "120": true,
}

var settingKeys = []string{
	"interval_minutes", "blocklist_typ", "source_url", "extra_sources", "delete_ip_after",
	"loglevel", "geoip_mode", "geoip_countries", "max_attempts",
	"fail_alert_after", "recovery_alert_after", "notify_lang", "scheduler_enabled",
	"debug_perf", "deny", "progressbar", "type", "meta", "geoip_db", "import_ipv6",
}

func validateSettings(in map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for _, key := range settingKeys {
		v, ok := in[key]
		if !ok {
			return nil, fmt.Errorf("missing %s", key)
		}
		norm, err := checkSetting(key, v)
		if err != nil {
			return nil, err
		}
		out[key] = norm
	}
	return out, nil
}

func checkSetting(key, v string) (string, error) {
	switch key {
	case "interval_minutes":
		v = strings.TrimSpace(v)
		if !intervalSteps[v] {
			return "", fmt.Errorf("interval must be one of 1, 5, 10, 15, 20, 30, 60, 120")
		}
		return v, nil
	case "blocklist_typ":
		if !blocklistTypes[v] {
			return "", fmt.Errorf("unknown blocklist type")
		}
		return v, nil
	case "source_url":
		u, err := url.Parse(strings.TrimSpace(v))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return "", fmt.Errorf("source must be an http(s) URL")
		}
		return u.String(), nil
	case "extra_sources":
		var list []string
		if err := json.Unmarshal([]byte(v), &list); err != nil {
			return "", fmt.Errorf("extra_sources must be a JSON array")
		}
		if len(list) > 20 {
			return "", fmt.Errorf("too many extra sources")
		}
		for _, raw := range list {
			u, err := url.Parse(raw)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return "", fmt.Errorf("extra source must be an http(s) URL")
			}
		}
		b, _ := json.Marshal(list)
		return string(b), nil
	case "delete_ip_after":
		return boundedInt(v, 0, 3650)
	case "loglevel":
		return boundedInt(v, 0, 2)
	case "geoip_mode":
		switch v {
		case "off", "blockonly", "blockother":
			return v, nil
		default:
			return "", fmt.Errorf("bad geoip mode")
		}
	case "geoip_countries":
		var list []string
		if err := json.Unmarshal([]byte(v), &list); err != nil {
			return "", fmt.Errorf("geoip_countries must be a JSON array")
		}
		for i, c := range list {
			c = strings.ToUpper(strings.TrimSpace(c))
			if len(c) != 2 {
				return "", fmt.Errorf("country code must have 2 letters")
			}
			list[i] = c
		}
		b, _ := json.Marshal(list)
		return string(b), nil
	case "max_attempts":
		return boundedInt(v, 1, 20)
	case "fail_alert_after", "recovery_alert_after":
		return boundedInt(v, 1, 100)
	case "notify_lang":
		v = strings.TrimSpace(v)
		if !notifyLangs[v] {
			return "", fmt.Errorf("unknown notification language")
		}
		return v, nil
	case "scheduler_enabled", "debug_perf", "progressbar", "import_ipv6":
		return boundedInt(v, 0, 1)
	case "deny":
		return boundedInt(v, 0, 1)
	case "type":
		return boundedInt(v, 0, 3)
	case "meta":
		if len(v) > 256 || strings.ContainsAny(v, "\r\n") {
			return "", fmt.Errorf("meta is too long")
		}
		return v, nil
	case "geoip_db":
		if !strings.HasPrefix(v, "/") || strings.Contains(v, "..") {
			return "", fmt.Errorf("geoip database path must be absolute")
		}
		return v, nil
	default:
		return "", fmt.Errorf("unknown setting")
	}
}

func boundedInt(v string, min, max int) (string, error) {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < min || n > max {
		return "", fmt.Errorf("value out of range")
	}
	return strconv.Itoa(n), nil
}
