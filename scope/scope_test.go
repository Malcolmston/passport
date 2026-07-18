package scope

import (
	"reflect"
	"testing"
)

func TestParseAndString(t *testing.T) {
	s := Parse("read   write read openid")
	if s.Len() != 3 {
		t.Errorf("Len = %d, want 3", s.Len())
	}
	if got := s.String(); got != "read write openid" {
		t.Errorf("String = %q", got)
	}
}

func TestParseEmpty(t *testing.T) {
	if Parse("").Len() != 0 {
		t.Error("empty parse should be empty")
	}
	if Parse("   ").Len() != 0 {
		t.Error("whitespace parse should be empty")
	}
}

func TestHasAndSlice(t *testing.T) {
	s := New("a", "b", "a", "")
	if !s.Has("a") || !s.Has("b") {
		t.Error("Has should find inserted scopes")
	}
	if s.Has("c") {
		t.Error("Has should not find absent scope")
	}
	if got := s.Slice(); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("Slice = %v", got)
	}
}

func TestAddRemove(t *testing.T) {
	base := New("a", "b")
	added := base.Add("c", "a")
	if got := added.String(); got != "a b c" {
		t.Errorf("Add = %q", got)
	}
	if base.Len() != 2 {
		t.Error("Add must not mutate the receiver")
	}
	removed := added.Remove("a", "z")
	if got := removed.String(); got != "b c" {
		t.Errorf("Remove = %q", got)
	}
}

func TestUnionIntersection(t *testing.T) {
	a := New("read", "write")
	b := New("write", "admin")
	if got := a.Union(b).String(); got != "read write admin" {
		t.Errorf("Union = %q", got)
	}
	if got := a.Intersection(b).String(); got != "write" {
		t.Errorf("Intersection = %q", got)
	}
}

func TestContainsEqual(t *testing.T) {
	a := New("read", "write", "admin")
	b := New("write", "read")
	if !a.Contains(b) {
		t.Error("a should contain b")
	}
	if b.Contains(a) {
		t.Error("b should not contain a")
	}
	if !a.Equal(New("admin", "read", "write")) {
		t.Error("Equal should ignore order")
	}
	if a.Equal(b) {
		t.Error("differently-sized sets are not equal")
	}
	if !a.Contains(New()) {
		t.Error("every set contains the empty set")
	}
}

func TestDiffFilter(t *testing.T) {
	a := New("read", "write", "admin")
	b := New("write")
	if got := a.Diff(b).String(); got != "read admin" {
		t.Errorf("Diff = %q", got)
	}
	kept := a.Filter(func(s string) bool { return s != "admin" })
	if got := kept.String(); got != "read write" {
		t.Errorf("Filter = %q", got)
	}
}

func TestSorted(t *testing.T) {
	s := New("c", "a", "b")
	if got := s.Sorted(); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Errorf("Sorted = %v", got)
	}
	if s.String() != "c a b" {
		t.Error("Sorted must not mutate insertion order")
	}
}
