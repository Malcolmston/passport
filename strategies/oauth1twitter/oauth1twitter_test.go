package oauth1twitter

import (
	"net/url"
	"testing"

	"github.com/malcolmston/passport/strategies/oauth1"
)

func TestNewNameAndConstruction(t *testing.T) {
	s := New(Config{
		ConsumerKey:    "ck",
		ConsumerSecret: "cs",
		CallbackURL:    "https://app.example/cb",
	}, func(at, as string, p url.Values) (any, error) { return "u", nil })

	if s == nil {
		t.Fatal("New returned nil")
	}
	if s.Name() != "twitter" {
		t.Errorf("Name() = %q, want %q", s.Name(), "twitter")
	}
	var _ *oauth1.Strategy = s
}
