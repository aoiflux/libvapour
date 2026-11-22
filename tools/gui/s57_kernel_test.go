package gui

import (
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/symbols"
)

const cookieAt = fuzzBase + 0x100

func cookieTable() *symbols.Table {
	t := symbols.NewTable("nt", 8)
	add := func(name string, members ...string) {
		fields := make([]symbols.Field, len(members))
		for i, m := range members {
			fields[i] = symbols.Field{Name: m, Offset: uint64(8 * i)}
		}
		t.AddStruct(symbols.StructType{Name: name, Size: uint64(8 * len(members)), Fields: fields})
	}
	add("_OBJECT_HEADER", "InfoMask", "TypeIndex", "Body")
	add("_ETHREAD", "Cid")
	add("_CLIENT_ID", "UniqueProcess", "UniqueThread")
	add("_EPROCESS", "UniqueProcessId", "ImageFileName")
	add("_OBJECT_HEADER_NAME_INFO", "Directory", "Name")
	t.AddSymbol(symbols.Symbol{Name: "ObpInfoMaskToOffset", Address: fuzzBase})
	t.AddSymbol(symbols.Symbol{Name: "ObHeaderCookie", Address: cookieAt})
	return t
}

func TestADeclaredCookieThatDoesNotReadRefusesTheKernelFacts(t *testing.T) {
	elsewhere := flat{base: cookieAt + 0x1000, data: make([]byte, 16)}
	if _, err := resolveKernel(cookieTable(), elsewhere); !errors.Is(err, ErrCookieUnread) {
		t.Errorf("unread: %v", err)
	}
	unplaced := testsupport.Unplaced(cookieTable(), "ObHeaderCookie")
	if _, err := resolveKernel(unplaced, elsewhere); !errors.Is(err, ErrCookieUnread) || !errors.Is(err, symbols.ErrNotPlaced) {
		t.Errorf("no running address: %v", err)
	}
	readable := flat{base: cookieAt, data: make([]byte, 16)}
	if _, err := resolveKernel(cookieTable(), readable); errors.Is(err, ErrCookieUnread) || !errors.Is(err, ErrNoKernelTypes) {
		t.Errorf("read, then the type table is missing: %v", err)
	}
}
