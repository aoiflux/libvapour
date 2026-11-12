package kernelpattern

import (
	"bytes"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/profiles"
)

func TestBytesMatchOneCharacterPerByte(t *testing.T) {
	p, err := CompilePattern(`\xffA.B`)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := p.Match([]byte{0x00, 0xff, 'A', '\n', 'B', 0x80})
	if !ok || !bytes.Equal(m, []byte{0xff, 'A', '\n', 'B'}) {
		t.Errorf("match = % x, %v", m, ok)
	}
	if _, ok := p.Match([]byte{0xc3, 0xbf, 'A', 'x', 'B'}); ok {
		t.Error("the UTF-8 encoding of U+00FF matched the byte 0xff")
	}
	if _, err := CompilePattern(""); err == nil {
		t.Error("an empty pattern compiled")
	}
}

func TestAMatchInTheLookaheadBelongsToTheNextChunk(t *testing.T) {
	p, _ := CompilePattern("XY")
	data := make([]byte, ChunkSize+Overlap)
	copy(data[ChunkSize-1:], "XY")
	copy(data[ChunkSize+10:], "XY")
	s := &Scanner{Pattern: p}
	var at []uint64
	s.Matches(data, 0x1000, func(a uint64, _ []byte) { at = append(at, a) })
	if len(at) != 1 || at[0] != 0x1000+ChunkSize-1 {
		t.Errorf("matches at %x, want only the one starting in the chunk", at)
	}
	s = &Scanner{Pattern: p, Limit: 1}
	copy(data[5:], "XY")
	at = nil
	s.Matches(data, 0, func(a uint64, _ []byte) { at = append(at, a) })
	if len(at) != 1 || s.Capped != 1 {
		t.Errorf("limit: %x capped %d", at, s.Capped)
	}
}

func TestCoalesceMergesOverlapsAndDropsEmptySections(t *testing.T) {
	got := Coalesce([]Section{{0x3000, 0x1000}, {0x1000, 0x1000}, {0x1800, 0x1000}, {0x9000, 0}})
	want := []Section{{0x1000, 0x1800}, {0x3000, 0x1000}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Coalesce = %+v", got)
	}
}

func TestTheKernelHalfIsSearchedAcrossFrames(t *testing.T) {
	k := testsupport.NewS64Kernel()
	va := k.Alloc(0x1000)
	k.Write(va+0xffc, []byte("NEED"))
	k.Alloc(0x3000)
	k.Write(va+0x1000, []byte("LE in a haystack"))
	if k.Physical(va+0x1000) == k.Physical(va)+0x1000 {
		t.Fatal("the fixture mapped the pages to adjacent frames")
	}
	ctx := k.Context()
	ctx.Options[OptionPattern] = "NEEDLE"
	ctx.Options[OptionMaxSize] = uint64(4)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Offset != va+0xffc || string(rows[0].Hex) != "NEED" || rows[0].Text != "NEED" {
		t.Errorf("rows = %+v", rows)
	}
}

func TestOnlyWindowsIsSearched(t *testing.T) {
	ctx := testsupport.NewS64Kernel().Context()
	ctx.Profile = profiles.LinuxX64Profile{}
	ctx.Options[OptionPattern] = "x"
	_, err := Run(ctx)
	if want := Name + `: unsupported profile os "linux"`; err == nil || err.Error() != want {
		t.Errorf("err %v, want %s", err, want)
	}
}

func TestOptions(t *testing.T) {
	ctx := testsupport.NewS64Kernel().Context()
	if _, err := Run(ctx); err == nil {
		t.Error("no pattern was accepted")
	}
	ctx.Options[OptionPattern] = "("
	if _, err := Run(ctx); err == nil {
		t.Error("a pattern RE2 refuses was accepted")
	}
	ctx.Options[OptionPattern] = "x"
	ctx.Options[OptionMaxSize] = uint64(0)
	if _, err := Run(ctx); err == nil {
		t.Error("a match size of 0 was accepted")
	}
	ctx.Options[OptionMaxSize] = uint64(1 << 40)
	if _, err := Run(ctx); err == nil {
		t.Error("a match size above MaxBufferBytes was accepted")
	}
	delete(ctx.Options, OptionMaxSize)
	if v, err := MaxSizeOption(ctx, OptionMaxSize); err != nil || v != uint64(ctx.Bounds().RowPreviewBytes) {
		t.Errorf("default match size %d %v", v, err)
	}
	if got := Truncate([]byte("abcdef"), 3); string(got) != "abc" {
		t.Errorf("Truncate = %q", got)
	}
}

func FuzzPatternMatches(f *testing.F) {
	f.Add([]byte("a\xffb\x00ab"), uint8(0))
	patterns := []string{`a.b`, `\xff`, `[\x80-\xff]+`, `ab|b`, `^a`}
	compiled := make([]*Pattern, len(patterns))
	for i, p := range patterns {
		compiled[i], _ = CompilePattern(p)
	}
	f.Fuzz(func(t *testing.T, data []byte, which uint8) {
		p := compiled[int(which)%len(compiled)]
		s := &Scanner{Pattern: p}
		last := -1
		s.Matches(data, 0, func(at uint64, m []byte) {
			if int(at) <= last || int(at)+len(m) > len(data) || !bytes.Equal(data[at:int(at)+len(m)], m) {
				t.Errorf("match at %d of %d bytes", at, len(m))
			}
			if _, ok := p.Match(data[at:]); !ok {
				t.Errorf("the pattern does not match from its own match at %d", at)
			}
			last = int(at)
		})
	})
}
