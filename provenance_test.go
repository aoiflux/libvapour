package libvapour

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	provenanceRoot = "docs/provenance"
	specRoot       = "docs/specs"
)

type provenanceRecord struct {
	path     string
	file     string
	spec     string
	specHash string
	sources  int
}

func readProvenance(t *testing.T, path string) provenanceRecord {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rec := provenanceRecord{path: path}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch {
		case !strings.HasPrefix(line, " ") && key == "file":
			rec.file = value
		case !strings.HasPrefix(line, " ") && key == "spec":
			rec.spec = value
		case !strings.HasPrefix(line, " ") && key == "spec_sha256":
			rec.specHash = value
		case strings.HasPrefix(strings.TrimSpace(line), "- title:"):
			rec.sources++
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return rec
}

// A rewritten file carries a record of the specification and sources it was
// written from. The spec hash pins the record to the spec text it names, so
// editing a spec without revisiting its records fails here.
func TestEveryRewrittenFileHasAProvenanceRecord(t *testing.T) {
	var records []provenanceRecord
	err := filepath.WalkDir(provenanceRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".yaml") {
			records = append(records, readProvenance(t, path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) == 0 {
		t.Fatal("no provenance records")
	}

	covered := map[string]bool{}
	dirs := map[string]bool{}
	for _, r := range records {
		if r.file == "" || r.spec == "" || r.specHash == "" || r.sources == 0 {
			t.Errorf("%s: needs file, spec, spec_sha256 and at least one source", r.path)
			continue
		}
		if _, err := os.Stat(r.file); err != nil {
			t.Errorf("%s: %v", r.path, err)
		}
		data, err := os.ReadFile(filepath.Join(specRoot, r.spec+".md"))
		if err != nil {
			t.Errorf("%s: %v", r.path, err)
			continue
		}
		if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != r.specHash {
			t.Errorf("%s: %s changed since the record was written; review the file and update spec_sha256", r.path, r.spec)
		}
		covered[filepath.ToSlash(r.file)] = true
		dirs[filepath.Dir(r.file)] = true
	}

	for dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			if p := filepath.ToSlash(filepath.Join(dir, name)); !covered[p] && !keptInRewrittenPackage[p] && !awaitingRewrite[p] {
				t.Errorf("%s is in a rewritten package but has no provenance record", p)
			}
		}
	}
}

// Files that share a package with a rewritten file but were classed as the
// project's own and kept.
var keptInRewrittenPackage = map[string]bool{}

// Files that share a package with a rewritten file and have a rewrite step of
// their own still to come. Listed so the gap stays visible.
var awaitingRewrite = map[string]bool{}
