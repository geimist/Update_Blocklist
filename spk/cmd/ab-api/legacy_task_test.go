package main

import "testing"

func TestParseLegacyTasks(t *testing.T) {
	got := parseLegacyTasks("93\tupdate_blocklist.sh\n7\tnightly\n\n")
	if len(got) != 2 || got[0].ID != "93" || got[0].Name != "update_blocklist.sh" || got[1].Name != "nightly" {
		t.Fatalf("unexpected %+v", got)
	}
	if len(parseLegacyTasks("")) != 0 {
		t.Fatal("empty output should yield no tasks")
	}
	if got := parseLegacyTasks("no-tab\n"); len(got) != 0 {
		t.Fatalf("ignored line was kept: %+v", got)
	}
}
