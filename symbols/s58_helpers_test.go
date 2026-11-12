package symbols

import (
	"errors"
	"testing"
)

type flat struct {
	base uint64
	data []byte
}

func (m flat) ReadAt(at, n uint64) ([]byte, error) {
	if at < m.base || at-m.base > uint64(len(m.data)) || n > uint64(len(m.data))-(at-m.base) {
		return nil, errors.New("outside the test memory")
	}
	return m.data[at-m.base : at-m.base+n], nil
}

func (m flat) Size() uint64 { return m.base + uint64(len(m.data)) }

type shortReader struct{}

func (shortReader) ReadAt(_, n uint64) ([]byte, error) { return make([]byte, n/2), nil }
func (shortReader) Size() uint64                       { return 1 << 20 }

func ref(t *testing.T, expr string) TypeRef {
	t.Helper()
	r, err := parseTypeExpression(expr)
	if err != nil {
		t.Fatalf("parse %q: %v", expr, err)
	}
	return r
}

func refp(t *testing.T, expr string) *TypeRef {
	r := ref(t, expr)
	return &r
}

func mustBuild(t *testing.T, d Declaration) *Table {
	t.Helper()
	table, err := Build("test", d)
	if err != nil {
		t.Fatal(err)
	}
	return table
}

var linuxScalars = []Scalar{
	{Name: "char", Width: 1, Kind: ScalarChar, Signed: true},
	{Name: "unsigned int", Width: 4, Kind: ScalarInteger},
	{Name: "long unsigned int", Width: 8, Kind: ScalarInteger},
	{Name: "double", Width: 8, Kind: ScalarFloat, Signed: true},
	{Name: "__be32", Width: 4, Kind: ScalarInteger, BigEndian: true},
	{Name: "void", Width: 0, Kind: ScalarVoid},
}
