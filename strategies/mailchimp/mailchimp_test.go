package mailchimp

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "mailchimp" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "mailchimp")
	}
}
