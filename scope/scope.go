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
func (s Set) Has(scope string) bool {
	_, ok := s.index[scope]
	return ok
}

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
