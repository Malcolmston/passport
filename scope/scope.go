// Package scope provides an ordered set type for working with OAuth 2.0 scope
// strings in the passport port. OAuth authorization requests carry scopes as a
// single space-delimited string, and provider presets accumulate, compare, and
// normalize them by hand; this package centralizes that logic so callers can
// parse a wire value, test membership, and combine scope collections without
// re-implementing string splitting each time.
//
// A Set preserves first-insertion order (so the rendered scope string is stable
// and diff-friendly) while rejecting duplicates. Every operation is pure and
// deterministic; the zero value is not usable — build sets with New or Parse.
package scope

import (
	"sort"
	"strings"
)

// Set is an insertion-ordered collection of unique OAuth scope tokens.
type Set struct {
	order []string
	index map[string]int
}

// New returns a Set containing the given scopes, de-duplicated and in the order
// first seen. Empty tokens are ignored.
func New(scopes ...string) Set {
	s := Set{index: make(map[string]int)}
	s.addAll(scopes)
	return s
}

// Parse splits a space-delimited scope string (as sent on the wire) into a Set,
// collapsing any runs of whitespace and dropping empty tokens.
func Parse(raw string) Set {
	return New(strings.Fields(raw)...)
}

// ParseSep splits a scope string on an explicit separator. RFC 6749 specifies a
// space, but several providers deviate — Facebook and LinkedIn use "," — which
// is why passport-oauth2 exposes a scopeSeparator option; ParseSep is the
// equivalent knob here. Surrounding whitespace is trimmed from each token and
// empty tokens are dropped, so "a, b,,c" parses to three scopes. An empty
// separator falls back to Parse's whitespace splitting.
func ParseSep(raw, sep string) Set {
	if sep == "" {
		return Parse(raw)
	}
	parts := strings.Split(raw, sep)
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return New(parts...)
}

func (s *Set) addAll(scopes []string) {
	for _, sc := range scopes {
		if sc == "" {
			continue
		}
		if _, ok := s.index[sc]; ok {
			continue
		}
		s.index[sc] = len(s.order)
		s.order = append(s.order, sc)
	}
}

// Has reports whether scope is present in the set.
//
// Membership is an exact, whole-token match against the parsed set — never a
// substring or prefix test on the raw scope string. That distinction is a
// security boundary: a naive strings.Contains check on "read admin" would
// report that the holder has "admin" when a provider granted only "readadmin",
// or that "user:read" satisfies a check for "user", silently escalating
// privilege. Callers gating on a scope should always go through Has, HasAll,
// or Contains rather than inspecting String().
func (s Set) Has(scope string) bool {
	_, ok := s.index[scope]
	return ok
}

// HasAll reports whether every one of the given scopes is present. It is the
// variadic form of Contains and the usual way to gate an operation that needs
// several scopes at once. With no arguments it reports true.
func (s Set) HasAll(scopes ...string) bool {
	for _, sc := range scopes {
		if !s.Has(sc) {
			return false
		}
	}
	return true
}

// HasAny reports whether at least one of the given scopes is present. With no
// arguments it reports false.
func (s Set) HasAny(scopes ...string) bool {
	for _, sc := range scopes {
		if s.Has(sc) {
			return true
		}
	}
	return false
}

// IsEmpty reports whether the set contains no scopes. It is true for the zero
// value as well as for a Set built from an empty or whitespace-only string.
func (s Set) IsEmpty() bool { return len(s.order) == 0 }

// Clone returns an independent copy of the set. Every other operation already
// returns a new Set rather than mutating the receiver, so Clone is needed only
// when a caller wants to hold a snapshot across an assignment.
func (s Set) Clone() Set { return New(s.order...) }

// Len returns the number of distinct scopes in the set.
func (s Set) Len() int { return len(s.order) }

// Slice returns the scopes as a new slice in insertion order.
func (s Set) Slice() []string {
	out := make([]string, len(s.order))
	copy(out, s.order)
	return out
}

// String renders the set as a single space-delimited scope string in insertion
// order, the form OAuth authorization requests expect.
func (s Set) String() string { return strings.Join(s.order, " ") }

// Join renders the set using an explicit separator, the counterpart to
// ParseSep for providers that do not use the RFC 6749 space.
func (s Set) Join(sep string) string { return strings.Join(s.order, sep) }

// MarshalText renders the set as its space-delimited wire form, so a Set used
// as a struct field encodes as a plain JSON string ("openid profile") rather
// than as an object. It implements encoding.TextMarshaler.
func (s Set) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText parses a space-delimited wire value into the receiver,
// replacing any existing contents. It implements encoding.TextUnmarshaler and
// never fails: every string is a valid scope list, and empty or whitespace-only
// input yields an empty Set.
func (s *Set) UnmarshalText(text []byte) error {
	*s = Parse(string(text))
	return nil
}

// Sorted returns the scopes sorted lexicographically, leaving the receiver
// unchanged.
func (s Set) Sorted() []string {
	out := s.Slice()
	sort.Strings(out)
	return out
}

// Add returns a new Set containing every scope in the receiver plus the given
// scopes. The receiver is not modified.
func (s Set) Add(scopes ...string) Set {
	out := New(s.order...)
	out.addAll(scopes)
	return out
}

// Remove returns a new Set with the given scopes deleted. Scopes not present
// are ignored. The receiver is not modified.
func (s Set) Remove(scopes ...string) Set {
	drop := make(map[string]bool, len(scopes))
	for _, sc := range scopes {
		drop[sc] = true
	}
	out := Set{index: make(map[string]int)}
	for _, sc := range s.order {
		if !drop[sc] {
			out.addAll([]string{sc})
		}
	}
	return out
}

// Union returns a new Set containing every scope from the receiver followed by
// any additional scopes from other.
func (s Set) Union(other Set) Set { return s.Add(other.order...) }

// Intersection returns a new Set of the scopes present in both sets, in the
// receiver's order.
func (s Set) Intersection(other Set) Set {
	out := Set{index: make(map[string]int)}
	for _, sc := range s.order {
		if other.Has(sc) {
			out.addAll([]string{sc})
		}
	}
	return out
}

// Contains reports whether the receiver includes every scope in other (i.e. the
// receiver is a superset of other). An empty other is always contained.
func (s Set) Contains(other Set) bool {
	for _, sc := range other.order {
		if !s.Has(sc) {
			return false
		}
	}
	return true
}

// Equal reports whether the two sets contain exactly the same scopes,
// regardless of order.
func (s Set) Equal(other Set) bool {
	return s.Len() == other.Len() && s.Contains(other)
}

// Diff returns a new Set of the scopes present in the receiver but absent from
// other, preserving the receiver's order. It is the complement of
// Intersection.
func (s Set) Diff(other Set) Set {
	out := Set{index: make(map[string]int)}
	for _, sc := range s.order {
		if !other.Has(sc) {
			out.addAll([]string{sc})
		}
	}
	return out
}

// Filter returns a new Set containing only the scopes for which keep returns
// true, in the receiver's order.
func (s Set) Filter(keep func(scope string) bool) Set {
	out := Set{index: make(map[string]int)}
	for _, sc := range s.order {
		if keep(sc) {
			out.addAll([]string{sc})
		}
	}
	return out
}
