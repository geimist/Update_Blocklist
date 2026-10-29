CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS state (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at    INTEGER NOT NULL,
  duration_ms   INTEGER NOT NULL,
  online_count  INTEGER NOT NULL,
  diffs         INTEGER NOT NULL,
  added         INTEGER NOT NULL,
  expired       INTEGER NOT NULL,
  geoip_skip    INTEGER NOT NULL,
  count_before  INTEGER NOT NULL,
  count_after   INTEGER NOT NULL,
  status        TEXT NOT NULL,
  message       TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS run_days (
  day          TEXT PRIMARY KEY,
  online_count INTEGER NOT NULL,
  added        INTEGER NOT NULL,
  count_after  INTEGER NOT NULL
);

INSERT OR IGNORE INTO settings(key, value) VALUES
  ('interval_minutes', '10'),
  ('blocklist_typ', 'all'),
  ('source_url', 'https://lists.blocklist.de/lists/all.txt'),
  ('extra_sources', '[]'),
  ('delete_ip_after', '7'),
  ('loglevel', '1'),
  ('geoip_mode', 'off'),
  ('geoip_countries', '["DE","CN"]'),
  ('max_attempts', '5'),
  ('fail_alert_after', '3'),
  ('recovery_alert_after', '6'),
  ('notify_lang', 'ger'),
  ('scheduler_enabled', '1'),
  ('debug_perf', '0'),
  ('deny', '1'),
  ('progressbar', '0'),
  ('type', '0'),
  ('meta', ''),
  ('geoip_db', '/var/db/geoip-database/GeoLite2-City.mmdb'),
  ('import_ipv6', '0');

INSERT OR IGNORE INTO state(key, value) VALUES
  ('fail_streak', '0'),
  ('success_streak', '0'),
  ('alert_state', '0');
