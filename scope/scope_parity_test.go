package scope

// Parity tests for RFC 6749 §3.3 (OAuth 2.0 "scope" request parameter).
//
// Source (authoritative, fixed spec values encoded directly):
//   https://www.rfc-editor.org/rfc/rfc6749#section-3.3
//
// RFC 6749 §3.3 text:
//   "The value of the scope parameter is expressed as a list of space-
//    delimited, case-sensitive strings ... If the value contains multiple
//    space-delimited strings, their order does not matter, and each string
//    adds an additional access range to the requested scope."
//
//   scope       = scope-token *( SP scope-token )
//   scope-token = 1*NQCHAR
//
// RFC 6749 Appendix A (ABNF):
//   NQCHAR = %x21 / %x23-5B / %x5D-7E
//   (any printable ASCII except SP %x20, double-quote %x22, and backslash %x5C;
//    control characters are also excluded.)

import (
	"reflect"
	"testing"
)

// TestParityParseSpaceDelimited: scope is a space-delimited list of tokens.
// parse("a b c") -> ["a","b","c"].
func TestParityParseSpaceDelimited(t *testing.T) {
	got := Parse("a b c").Slice()
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Parse(%q).Slice() = %v, want %v", "a b c", got, want)
	}
}

// TestParitySerializeSingleSP: rendering joins tokens with a single SP.
// serialize(["a","b"]) -> "a b".
func TestParitySerializeSingleSP(t *testing.T) {
	if got := New("a", "b").String(); got != "a b" {
		t.Errorf("New(a,b).String() = %q, want %q", got, "a b")
	}
	// Real-world OAuth example scope value round-trips exactly.
	const wire = "openid profile email"
	if got := Parse(wire).String(); got != wire {
		t.Errorf("Parse(%q).String() = %q, want %q", wire, got, wire)
	}
}

// TestParityCaseSensitive: scope-tokens are case-sensitive; "read" != "READ".
func TestParityCaseSensitive(t *testing.T) {
	s := Parse("read READ Read")
	if s.Len() != 3 {
		t.Fatalf("case-sensitive tokens collapsed: Len = %d, want 3", s.Len())
	}
	if !s.Has("read") || !s.Has("READ") || !s.Has("Read") {
		t.Error("Has should distinguish case-variant tokens")
	}
	if s.Has("reAd") {
		t.Error("Has must not match a token differing only in case")
	}
	if !Parse("a").Equal(Parse("a")) {
		t.Error("identical tokens should be equal")
	}
	if Parse("a").Equal(Parse("A")) {
		t.Error("case-variant single-token sets must not be equal")
	}
}

// TestParityOrderDoesNotMatterForEquality: §3.3 says token order does not
// matter; Equal must be order-independent while String preserves order.
func TestParityOrderDoesNotMatterForEquality(t *testing.T) {
	if !Parse("a b c").Equal(Parse("c b a")) {
		t.Error("Equal should ignore token order per §3.3")
	}
	if got := Parse("c b a").String(); got != "c b a" {
		t.Errorf("String should preserve wire order: got %q", got)
	}
}

// TestParityDedup: a repeated token adds no additional access range; the
// de-duplicated set carries the token once.
func TestParityDedup(t *testing.T) {
	s := Parse("a b a c b")
	if s.Len() != 3 {
		t.Fatalf("dedup failed: Len = %d, want 3", s.Len())
	}
	if got := s.String(); got != "a b c" {
		t.Errorf("dedup String = %q, want %q", got, "a b c")
	}
}

// TestParityEmpty: an empty or whitespace-only scope value yields no tokens
// (scope-token = 1*NQCHAR, so empty tokens are not representable).
func TestParityEmpty(t *testing.T) {
	if n := Parse("").Len(); n != 0 {
		t.Errorf("Parse(\"\").Len() = %d, want 0", n)
	}
	if n := Parse("   ").Len(); n != 0 {
		t.Errorf("Parse of spaces .Len() = %d, want 0", n)
	}
	if got := New().String(); got != "" {
		t.Errorf("empty set String = %q, want \"\"", got)
	}
	if n := New("", "a", "").Len(); n != 1 {
		t.Errorf("empty tokens must be dropped: Len = %d, want 1", n)
	}
}

// TestParityHasAddRemove: membership and mutation on the token set.
func TestParityHasAddRemove(t *testing.T) {
	s := Parse("read write")
	if !s.Has("read") || !s.Has("write") || s.Has("admin") {
		t.Error("Has membership incorrect")
	}
	added := s.Add("admin", "read") // "read" already present -> no dup
	if got := added.String(); got != "read write admin" {
		t.Errorf("Add String = %q, want %q", got, "read write admin")
	}
	if s.Len() != 2 {
		t.Error("Add must not mutate the receiver")
	}
	removed := added.Remove("write", "absent")
	if got := removed.String(); got != "read admin" {
		t.Errorf("Remove String = %q, want %q", got, "read admin")
	}
}

// TestParityNQCHARTokens: NQCHAR admits every printable ASCII char except
// SP (0x20), DQUOTE (0x22), and backslash (0x5C). Such tokens must survive a
// parse/serialize round-trip intact and not be split further.
func TestParityNQCHARTokens(t *testing.T) {
	// Representative real OAuth scope tokens using NQCHAR punctuation:
	// URI-style (Google/Azure), colon-style (GitHub), dot-style.
	tokens := []string{
		"https://www.googleapis.com/auth/drive.readonly",
		"user:email",
		"repo:status",
		"admin.write",
		"a!#$%&'()*+,-./:;<=>?@[]^_`{|}~b", // dense NQCHAR sampler (no SP/DQUOTE/backslash)
	}
	for _, tok := range tokens {
		s := Parse(tok)
		if s.Len() != 1 {
			t.Errorf("Parse(%q).Len() = %d, want 1 (token must not be split)", tok, s.Len())
			continue
		}
		if !s.Has(tok) {
			t.Errorf("Parse(%q) lost the token", tok)
		}
		if got := s.String(); got != tok {
			t.Errorf("round-trip: Parse(%q).String() = %q", tok, got)
		}
	}
	// A multi-token line of NQCHAR tokens splits only on SP.
	line := "user:email repo:status admin.write"
	got := Parse(line).Slice()
	want := []string{"user:email", "repo:status", "admin.write"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Parse(%q).Slice() = %v, want %v", line, got, want)
	}
}
