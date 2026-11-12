package processidentity

import (
	"encoding/binary"
	"slices"
	"testing"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/symbols"
)

const (
	sAuditMember   = uint64(0x5c0)
	sParamsMember  = uint64(0x20)
	sBlockLength   = uint64(0x4)
	sImagePathName = uint64(0x60)
	sCommandLine   = uint64(0x70)

	sPebVA     = uint64(0x7ff700000000)
	sParamsVA  = uint64(0x7ff700010000)
	sOutsideVA = uint64(0x7ff700020000)
	sBlockSize = uint64(0x1000)
	sAuditVA   = uint64(0xffff900000000000)
)

// A string as the loader lays it out: the text, a NUL after it, and
// MaximumLength two bytes past Length (S68 M6, M7).
type sString struct {
	text    string
	length  int
	maximum int
	noNUL   bool
	outside bool
}

func (s sString) units() []uint16 { return utf16.Encode([]rune(s.text)) }

func (s sString) lengths() (uint16, uint16) {
	l := 2 * len(s.units())
	if s.length != 0 {
		l = s.length
	}
	m := l + 2
	if s.maximum != 0 {
		m = s.maximum
	}
	return uint16(l), uint16(m)
}

type sProcess struct {
	pid        uint64
	name       string
	kernelPath string
	noAudit    bool
	noPeb      bool
	noParams   bool
	image, cmd sString
}

func sBytes(units []uint16, nul bool) []byte {
	if nul {
		units = append(slices.Clone(units), 0)
	}
	out := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(out[2*i:], u)
	}
	return out
}

func sTable(f *testsupport.ProcessFixture) {
	add := func(name string, fields ...symbols.Field) {
		st, err := f.Table.Struct(name)
		if err != nil {
			st = symbols.StructType{Name: name, Size: 0x100}
		}
		st.Fields = append(slices.Clone(st.Fields), fields...)
		f.Table.AddStruct(st)
	}
	add("_EPROCESS", symbols.Field{Name: "SeAuditProcessCreationInfo", Offset: sAuditMember})
	add("_SE_AUDIT_PROCESS_CREATION_INFO", symbols.Field{Name: "ImageFileName", Offset: 0})
	add("_OBJECT_NAME_INFORMATION", symbols.Field{Name: "Name", Offset: 0, Type: symbols.TypeRef{Name: "_UNICODE_STRING"}})
	add("_PEB", symbols.Field{Name: "ProcessParameters", Offset: sParamsMember})
	add("_RTL_USER_PROCESS_PARAMETERS",
		symbols.Field{Name: "MaximumLength", Offset: 0}, symbols.Field{Name: "Length", Offset: sBlockLength},
		symbols.Field{Name: "ImagePathName", Offset: sImagePathName, Type: symbols.TypeRef{Name: "_UNICODE_STRING"}},
		symbols.Field{Name: "CommandLine", Offset: sCommandLine, Type: symbols.TypeRef{Name: "_UNICODE_STRING"}})
}

func sFixture(procs ...sProcess) *testsupport.ProcessFixture {
	var fp []testsupport.FixtureProcess
	for _, p := range procs {
		fp = append(fp, testsupport.FixtureProcess{PID: p.pid, Name: p.name, NoPeb: true})
	}
	f := testsupport.BuildProcessFixture(fp)
	sTable(f)
	for i, p := range procs {
		_, ep := f.EPROCESS(p.pid)
		if !p.noAudit {
			at := sAuditVA + uint64(i)*0x10000
			raw := sBytes(utf16.Encode([]rune(p.kernelPath)), true)
			info := make([]byte, 0x1000)
			binary.LittleEndian.PutUint16(info[0x10:], uint16(len(raw)-2))
			binary.LittleEndian.PutUint16(info[0x12:], uint16(len(raw)))
			binary.LittleEndian.PutUint64(info[0x18:], at+0x100)
			copy(info[0x100:], raw)
			f.Kernel.MapData(at, info)
			f.Memory.WriteU64(ep+sAuditMember, at+0x10)
		}
		if p.noPeb {
			continue
		}
		f.Memory.WriteU64(ep+testsupport.FixturePebOffset, sPebVA)
		space := f.Space(p.pid)
		peb := make([]byte, 0x1000)
		if !p.noParams {
			binary.LittleEndian.PutUint64(peb[sParamsMember:], sParamsVA)
		}
		space.MapData(sPebVA, peb)
		block := make([]byte, sBlockSize)
		outside := make([]byte, 0x1000)
		binary.LittleEndian.PutUint32(block[0:], uint32(sBlockSize))
		binary.LittleEndian.PutUint32(block[sBlockLength:], uint32(sBlockSize))
		for j, s := range []struct {
			at uint64
			s  sString
		}{{sImagePathName, p.image}, {sCommandLine, p.cmd}} {
			l, m := s.s.lengths()
			binary.LittleEndian.PutUint16(block[s.at:], l)
			binary.LittleEndian.PutUint16(block[s.at+2:], m)
			raw := sBytes(s.s.units(), !s.s.noNUL)
			buf := sParamsVA + 0x200 + uint64(j)*0x600
			if s.s.outside {
				buf = sOutsideVA + uint64(j)*0x800
				copy(outside[uint64(j)*0x800:], raw)
			} else {
				copy(block[buf-sParamsVA:], raw)
			}
			binary.LittleEndian.PutUint64(block[s.at+8:], buf)
		}
		space.MapData(sParamsVA, block)
		space.MapData(sOutsideVA, outside)
	}
	return f
}

func symbolsWithout(t testing.TB, f *testsupport.ProcessFixture, name string, drop ...string) symbols.StructType {
	t.Helper()
	st, err := f.Table.Struct(name)
	if err != nil {
		t.Fatal(err)
	}
	st.Fields = slices.DeleteFunc(slices.Clone(st.Fields), func(fl symbols.Field) bool { return slices.Contains(drop, fl.Name) })
	return st
}
