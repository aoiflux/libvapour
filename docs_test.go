package libvapour

import (
	"errors"
	"go/ast"
	"go/build"
	"go/doc"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"testing"
)

var corePackages = []string{
	".", "memory", "layers", "symbols", "scan", "pe", "minidump",
	"extract", "disasm", "util", "objects", "profiles",
}

func importDir(t *testing.T, dir string) *build.Package {
	t.Helper()
	bp, err := build.ImportDir(dir, 0)
	var noGo *build.NoGoError
	if errors.As(err, &noGo) {
		return nil
	}
	if err != nil {
		t.Fatalf("import %s: %v", dir, err)
	}
	return bp
}

func parseFiles(t *testing.T, dir string, names []string) (*token.FileSet, []*ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	files := make([]*ast.File, 0, len(names))
	for _, name := range names {
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", filepath.Join(dir, name), err)
		}
		files = append(files, f)
	}
	return fset, files
}

func TestEveryCorePackageHasAnExample(t *testing.T) {
	for _, dir := range corePackages {
		bp := importDir(t, dir)
		if bp == nil {
			t.Errorf("%s: core package has no Go files", dir)
			continue
		}
		_, files := parseFiles(t, dir, slices.Concat(bp.TestGoFiles, bp.XTestGoFiles))
		if len(doc.Examples(files...)) == 0 {
			t.Errorf("%s: core package has no Example", dir)
		}
	}
}
