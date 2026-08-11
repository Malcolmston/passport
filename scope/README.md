# scope — provides an ordered set type for working with OAuth 2.0 scope strings in the passport

[![Go Reference](https://pkg.go.dev/badge/github.com/malcolmston/passport/scope.svg)](https://pkg.go.dev/github.com/malcolmston/passport/scope)

Package scope provides an ordered set type for working with OAuth 2.0 scope
strings in the passport port. OAuth authorization requests carry scopes as a
single space-delimited string, and provider presets accumulate, compare, and
normalize them by hand; this package centralizes that logic so callers can
parse a wire value, test membership, and combine scope collections without
re-implementing string splitting each time.

A Set preserves first-insertion order (so the rendered scope string is stable
and diff-friendly) while rejecting duplicates. Every operation is pure and
deterministic; the zero value is not usable — build sets with New or Parse.

## Install

```sh
go get github.com/malcolmston/passport@v0.4.0
```

```go
import "github.com/malcolmston/passport/scope"
```

## Usage

This is the package's own `ExampleParse`, so it compiles and its output is
asserted on every `go test ./scope/`.

```go
granted := scope.Parse("openid  profile email")

	fmt.Println("count:  ", granted.Len())
	fmt.Println("email:  ", granted.Has("email"))
	fmt.Println("admin:  ", granted.Has("admin"))
	fmt.Println("rendered:", granted)
```

```
count:   3
email:   true
admin:   false
rendered: openid profile email
```

## Exported surface

### Types

| Type | What it is |
| --- | --- |
| `Set` | Set is an insertion-ordered collection of unique OAuth scope tokens. |

<details>
<summary><code>Set</code> — constructors and methods</summary>

| Signature | What it does |
| --- | --- |
| `func New(scopes ...string) Set` | New returns a Set containing the given scopes, de-duplicated and in the order first seen. |
| `func Parse(raw string) Set` | Parse splits a space-delimited scope string (as sent on the wire) into a Set, collapsing any runs of whitespace and dropping empty tokens. |
| `func ParseSep(raw, sep string) Set` | ParseSep splits a scope string on an explicit separator. |
| `func (s Set) Add(scopes ...string) Set` | Add returns a new Set containing every scope in the receiver plus the given scopes. |
| `func (s Set) Clone() Set` | Clone returns an independent copy of the set. |
| `func (s Set) Contains(other Set) bool` | Contains reports whether the receiver includes every scope in other (i.e. |
| `func (s Set) Diff(other Set) Set` | Diff returns a new Set of the scopes present in the receiver but absent from other, preserving the receiver's order. |
| `func (s Set) Equal(other Set) bool` | Equal reports whether the two sets contain exactly the same scopes, regardless of order. |
| `func (s Set) Filter(keep func(scope string) bool) Set` | Filter returns a new Set containing only the scopes for which keep returns true, in the receiver's order. |
| `func (s Set) Has(scope string) bool` | Has reports whether scope is present in the set. |
| `func (s Set) HasAll(scopes ...string) bool` | HasAll reports whether every one of the given scopes is present. |
| `func (s Set) HasAny(scopes ...string) bool` | HasAny reports whether at least one of the given scopes is present. |
| `func (s Set) Intersection(other Set) Set` | Intersection returns a new Set of the scopes present in both sets, in the receiver's order. |
| `func (s Set) IsEmpty() bool` | IsEmpty reports whether the set contains no scopes. |
| `func (s Set) Join(sep string) string` | Join renders the set using an explicit separator, the counterpart to ParseSep for providers that do not use the RFC 6749 space. |
| `func (s Set) Len() int` | Len returns the number of distinct scopes in the set. |
| `func (s Set) MarshalText() ([]byte, error)` | MarshalText renders the set as its space-delimited wire form, so a Set used as a struct field encodes as a plain JSON string ("openid profile")… |
| `func (s Set) Remove(scopes ...string) Set` | Remove returns a new Set with the given scopes deleted. |
| `func (s Set) Slice() []string` | Slice returns the scopes as a new slice in insertion order. |
| `func (s Set) Sorted() []string` | Sorted returns the scopes sorted lexicographically, leaving the receiver unchanged. |
| `func (s Set) String() string` | String renders the set as a single space-delimited scope string in insertion order, the form OAuth authorization requests expect. |
| `func (s Set) Union(other Set) Set` | Union returns a new Set containing every scope from the receiver followed by any additional scopes from other. |
| `func (s *Set) UnmarshalText(text []byte) error` | UnmarshalText parses a space-delimited wire value into the receiver, replacing any existing contents. |

</details>

Full signatures, doc comments and every runnable example are on
[pkg.go.dev](https://pkg.go.dev/github.com/malcolmston/passport/scope).

## Deviations from upstream

Deliberate differences for this package, where any exist, are recorded in the
module-wide [`API-DEVIATIONS.md`](../API-DEVIATIONS.md).

## License

MIT, as part of [`github.com/malcolmston/passport`](..).
An independent re-implementation, not affiliated with or endorsed by the
original project.
