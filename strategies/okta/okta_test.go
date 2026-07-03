package okta

import (
	"strings"
	"testing"
)

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "okta" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "okta")
	}
}

func TestNewWithDomain(t *testing.T) {
	s := NewWithDomain("tenant.example.com", "id", "secret", "https://app.example/callback", nil)
	if s.Name() != "okta" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "okta")
	}
	if !strings.Contains(s.AuthCodeURL("st"), "tenant.example.com") {
		t.Fatalf("auth url does not use domain: %s", s.AuthCodeURL("st"))
	}
}
