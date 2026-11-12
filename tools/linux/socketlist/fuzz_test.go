package socketlist

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
)

func FuzzUnixPath(f *testing.F) {
	f.Add(int64(12), []byte("/run/a.sock\x00"))
	f.Add(int64(4), []byte("\x00a\x00b"))
	f.Add(int64(109), bytes.Repeat([]byte{'x'}, 109))
	f.Add(int64(110), []byte{})
	f.Fuzz(func(t *testing.T, n int64, path []byte) {
		s, err := UnixPath(n, path)
		if err != nil {
			if n >= 1 && n <= sunPathMax+1 && int64(len(path)) >= n {
				t.Fatalf("n %d with %d bytes refused: %v", n, len(path), err)
			}
			return
		}
		if strings.IndexByte(s, 0) >= 0 {
			t.Fatalf("%q holds a NUL", s)
		}
		if path[0] == 0 {
			if len(s) != int(n) || s[0] != '@' {
				t.Fatalf("abstract name %q from %d bytes", s, n)
			}
			return
		}
		want := strings.ReplaceAll(string(path[:n-1]), string(rune(0)), "@")
		if s != want {
			t.Fatalf("path name %q from %d bytes %q", s, n, path[:n])
		}
	})
}

func FuzzAddresses(f *testing.F) {
	f.Add([]byte{127, 0, 0, 1})
	f.Add([]byte{0xfe, 0x80, 15: 1})
	f.Add([]byte{0, 22})
	f.Fuzz(func(t *testing.T, b []byte) {
		if s, err := IPv4(b); err == nil {
			a, perr := netip.ParseAddr(s)
			if perr != nil || a.As4() != [4]byte(b) {
				t.Fatalf("%x renders as %q", b, s)
			}
		} else if len(b) == 4 {
			t.Fatal(err)
		}
		if s, err := IPv6(b); err == nil {
			a, perr := netip.ParseAddr(s)
			if perr != nil || a.As16() != [16]byte(b) {
				t.Fatalf("%x renders as %q", b, s)
			}
		} else if len(b) == 16 {
			t.Fatal(err)
		}
		if p, err := Port(b); err == nil && (len(b) != 2 || p != uint16(b[0])<<8|uint16(b[1])) {
			t.Fatalf("%x is port %d", b, p)
		}
	})
}

// A mapped sock whose family bytes and unix address are arbitrary always
// decodes: what does not read or does not fit only leaves fields absent.
func FuzzDecode(f *testing.F) {
	f.Add(uint16(afUnix), []byte{}, []byte("\x00\x00\x00\x00\x0e\x00\x00\x00\x01\x00/x\x00"))
	f.Add(uint16(afInet), []byte{1, 2, 3, 4}, []byte{})
	f.Add(uint16(afNetlink), bytes.Repeat([]byte{0xff}, 0x40), []byte{})
	f.Add(uint16(afPacket), bytes.Repeat([]byte{0x41}, 0x40), []byte{})
	f.Fuzz(func(t *testing.T, family uint16, body, addr []byte) {
		if len(body) > familySize-sockSize || len(addr) > 0x80 {
			return
		}
		fx := newFixture(layout{})
		s := fx.sock(spec{family: family, typ: 1})
		m := fx.k.Mem
		m.Write(s.sk+sockSize, body)
		a := fx.k.Alloc(0x80)
		m.Write(a, addr)
		m.U64(s.sk+unixAddr, a)
		m.U64(s.sk+skcNet, fx.initNet)
		m.Write(s.sk+skcFamily, []byte{byte(family), byte(family >> 8)})
		d, err := NewDecoder(newKernel(fx))
		if err != nil {
			t.Fatal(err)
		}
		got, err := d.Decode(fx.k.Mem, s.sk)
		if err != nil {
			t.Fatalf("a mapped sock does not decode: %v", err)
		}
		if got.Family != FamilyName(uint64(family)) || got.Coverage == "" {
			t.Fatalf("decoded %+v", got)
		}
	})
}
