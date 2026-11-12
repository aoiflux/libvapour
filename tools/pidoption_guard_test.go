package tools

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// A tool that read pid with a single-value reader would treat a list as an
// error or one PID, and bypass the PID 0, empty-list and range rules.
func TestToolsReadThePIDOptionOnlyThroughPIDs(t *testing.T) {
	readers := map[string]bool{"BoolOption": true, "UintOption": true, "StringOption": true,
		"StringListOption": true, "UintListOption": true, "PatternOption": true}
	isPIDKey := func(e ast.Expr) bool {
		switch k := e.(type) {
		case *ast.BasicLit:
			s, err := strconv.Unquote(k.Value)
			return k.Kind == token.STRING && err == nil && s == optionPID
		case *ast.Ident:
			return k.Name == "optionPID"
		}
		return false
	}
	parsed := 0
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		parsed++
		if filepath.Dir(path) == "." {
			return nil
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok && readers[sel.Sel.Name] && len(x.Args) > 0 && isPIDKey(x.Args[0]) {
					t.Errorf("%s: %s reads pid; use PIDs", fset.Position(x.Pos()), sel.Sel.Name)
				}
			case *ast.IndexExpr:
				if sel, ok := x.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "Options" && isPIDKey(x.Index) {
					t.Errorf("%s: Options indexed with pid; use PIDs", fset.Position(x.Pos()))
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if parsed < 100 {
		t.Fatalf("parsed %d files; the walk missed the tool packages", parsed)
	}
}
