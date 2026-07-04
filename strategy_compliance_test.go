package passport

// This file is an ENFORCED, static compliance runner for the strategy catalog
// under strategies/. It does not import any strategy package; instead it parses
// their source with go/parser and asserts a structural contract so that FUTURE
// strategies cannot merge without honoring it:
//
//   (a) the package provides a passport.Strategy, and
//   (b) the package ships at least one _test.go file.
//
// "Provides a passport.Strategy" is satisfied in either of two honest ways:
//
//   1. Direct implementation: the package declares both a Name method and an
//      Authenticate method (FuncDecl with a non-nil receiver) on some type —
//      this is the shape of the base strategies (oauth2, basic, bearer, ...).
//
//   2. Delegating preset: the package is a thin provider preset that imports a
//      sibling strategies/<base> package and exposes an exported constructor
//      returning that base's Strategy type (e.g. func New(...) *oauth2.Strategy).
//      The vast majority of the catalog — every OAuth2 provider preset and the
//      oauth1twitter preset — is this shape. Such a package genuinely provides a
//      passport.Strategy by composition, so counting it as compliant is the
//      honest reading of requirement (a); enumerating ~70 presets in the exempt
//      map instead would defeat "keep the exempt list as small as possible".
//
// Either way, a brand-new strategies/<name>/ package that ships no Strategy and
// no delegation, or no test, fails this test loudly.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// exempt lists subdirectories of strategies/ that are Go packages but are NOT
// themselves (and do not provide) a passport.Strategy — e.g. a shared helper,
// util, or internal support package. The key is the directory name; the value
// is a short reason. It is intentionally empty: today every Go package under
// strategies/ either implements a Strategy directly or is a delegating preset,
// so there is nothing to legitimately exempt. Add an entry here ONLY when a real
// non-strategy support package is introduced, with an honest one-line reason.
var exempt = map[string]string{}

func TestStrategyPackagesAreCompliant(t *testing.T) {
	const root = "strategies"

	// os.ReadDir returns entries sorted by name, so accumulating violations in
	// iteration order yields a naturally sorted report without a sort import.
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}

	var (
		violations []string
		checked    int
	)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		dir := filepath.Join(root, name)

		// Gather the package's .go files, split into production and test.
		files, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		var prod []string
		hasTest := false
		for _, f := range files {
			fn := f.Name()
			if f.IsDir() || !strings.HasSuffix(fn, ".go") {
				continue
			}
			if strings.HasSuffix(fn, "_test.go") {
				hasTest = true
				continue
			}
			prod = append(prod, filepath.Join(dir, fn))
		}

		// A subdirectory with no production .go file is not a Go package (and
		// therefore not a strategy); skip it silently.
		if len(prod) == 0 {
			continue
		}

		if reason, ok := exempt[name]; ok {
			t.Logf("skipping exempt package %q: %s", name, reason)
			continue
		}

		checked++

		provides, err := packageProvidesStrategy(prod)
		if err != nil {
			t.Fatalf("parse %s: %v", dir, err)
		}

		var missing []string
		if !provides {
			missing = append(missing, "a Strategy implementation (declare Name+Authenticate methods, or a preset returning a sibling strategy's *Strategy)")
		}
		if !hasTest {
			missing = append(missing, "at least one _test.go file")
		}
		if len(missing) > 0 {
			violations = append(violations, "  strategies/"+name+": missing "+strings.Join(missing, "; "))
		}
	}

	if checked == 0 {
		t.Fatalf("no strategy packages were checked under %s/ — the runner is misconfigured", root)
	}
	t.Logf("checked %d strategy packages under %s/", checked, root)

	if len(violations) > 0 {
		t.Fatalf("%d strategy package(s) violate the compliance contract:\n%s\n\n"+
			"Every strategies/<name>/ package must expose a passport.Strategy "+
			"(Name+Authenticate, or a preset delegating to a base strategy) and ship at least one test.",
			len(violations), strings.Join(violations, "\n"))
	}
}

// packageProvidesStrategy parses the given production (non-test) files of a
// single package and reports whether the package provides a passport.Strategy,
// either by declaring Name+Authenticate methods or by delegating to a sibling
// strategies/<base> package via an exported constructor.
func packageProvidesStrategy(files []string) (bool, error) {
	fset := token.NewFileSet()

	var hasName, hasAuthenticate, delegates bool
	// Local import names that refer to a sibling package under strategies/.
	baseImports := map[string]bool{}
	var fileASTs []*ast.File

	for _, path := range files {
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return false, err
		}
		fileASTs = append(fileASTs, file)

		for _, imp := range file.Imports {
			p := strings.Trim(imp.Path.Value, "`\"")
			if !strings.Contains(p, "/strategies/") {
				continue
			}
			local := ""
			if imp.Name != nil {
				local = imp.Name.Name
			} else if i := strings.LastIndex(p, "/"); i >= 0 {
				local = p[i+1:]
			}
			if local != "" && local != "_" && local != "." {
				baseImports[local] = true
			}
		}
	}

	for _, file := range fileASTs {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if fn.Recv != nil && len(fn.Recv.List) > 0 {
				switch fn.Name.Name {
				case "Name":
					hasName = true
				case "Authenticate":
					hasAuthenticate = true
				}
				continue
			}
			// A nil-receiver exported func returning a sibling strategy's
			// Strategy type marks a delegating preset.
			if fn.Name.IsExported() && returnsBaseStrategy(fn, baseImports) {
				delegates = true
			}
		}
	}

	return (hasName && hasAuthenticate) || delegates, nil
}

// returnsBaseStrategy reports whether fn returns a type selected from one of the
// given sibling strategy imports (e.g. *oauth2.Strategy or oauth1.Strategy).
func returnsBaseStrategy(fn *ast.FuncDecl, baseImports map[string]bool) bool {
	if fn.Type.Results == nil {
		return false
	}
	for _, result := range fn.Type.Results.List {
		if selectsBaseImport(result.Type, baseImports) {
			return true
		}
	}
	return false
}

// selectsBaseImport unwraps pointer types and reports whether expr is a selector
// pkg.Name where pkg is one of the sibling strategy imports.
func selectsBaseImport(expr ast.Expr, baseImports map[string]bool) bool {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return selectsBaseImport(t.X, baseImports)
	case *ast.SelectorExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return baseImports[id.Name]
		}
	}
	return false
}
