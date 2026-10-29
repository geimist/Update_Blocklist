package main

import "testing"

func TestLoginCGIEnvForcesGet(t *testing.T) {
	env := loginCGIEnv([]string{
		"REQUEST_METHOD=POST",
		"CONTENT_LENGTH=12",
		"CONTENT_TYPE=application/json",
		"HTTP_COOKIE=id=abc",
	})
	got := map[string]bool{}
	for _, e := range env {
		got[e] = true
	}
	if !got["REQUEST_METHOD=GET"] || got["REQUEST_METHOD=POST"] {
		t.Fatalf("method: %v", env)
	}
	if got["CONTENT_LENGTH=12"] || got["CONTENT_TYPE=application/json"] {
		t.Fatalf("body headers kept: %v", env)
	}
	if !got["HTTP_COOKIE=id=abc"] {
		t.Fatalf("cookie dropped: %v", env)
	}
}

func TestLoginSuccess(t *testing.T) {
	if !loginSuccess("{\"success\": true}") {
		t.Fatal("expected success")
	}
	if loginSuccess("{\"success\": false}") {
		t.Fatal("expected rejection")
	}
	if loginSuccess("Access denied") {
		t.Fatal("expected rejection")
	}
}
